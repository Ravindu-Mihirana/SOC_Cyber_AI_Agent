"""Direct scanner adapters shared by the UI; all invocations avoid a shell."""

import os
import re
import shutil
import subprocess
import uuid
import json
import time
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse, urlunparse
from urllib.request import Request, urlopen

from .models import Finding
from .nmap_parser import parse_nmap_xml
from .report_importers import _cves
from .storage import data_dir
from .web_parsers import parse_gobuster_text, parse_nikto_json, parse_nikto_text

SCANNERS = ("nmap", "burp", "nikto", "gobuster", "zap", "nuclei", "ffuf", "sqlmap")


class ScannerError(RuntimeError):
    pass


def _nikto_command() -> list[str] | None:
    direct = shutil.which("nikto")
    if direct:
        return [direct]
    script = os.environ.get("NIKTO_SCRIPT")
    perl = shutil.which("perl")
    if script and Path(script).is_file() and perl:
        return [perl, script]
    return None


def scanner_availability() -> dict[str, tuple[bool, str]]:
    nmap = shutil.which("nmap")
    gobuster = shutil.which("gobuster")
    nikto = _nikto_command()
    burp_configured = bool(os.environ.get("BURP_API_URL") and os.environ.get("BURP_API_KEY"))
    zap = shutil.which("zaproxy") or shutil.which("zap.sh") or shutil.which("zap.bat")
    nuclei = shutil.which("nuclei")
    ffuf = shutil.which("ffuf")
    sqlmap = shutil.which("sqlmap") or shutil.which("sqlmap.py")
    return {
        "nmap": (bool(nmap), nmap or "Nmap executable not found on PATH"),
        "burp": (burp_configured, os.environ.get("BURP_API_URL", "Configure Burp REST API URL and key in the assessment form")),
        "nikto": (bool(nikto), " ".join(nikto) if nikto else "Install Nikto and Perl; set NIKTO_SCRIPT if using nikto.pl"),
        "gobuster": (bool(gobuster), gobuster or "Gobuster executable not found on PATH"),
        "zap": (bool(zap), zap or "ZAP executable not found on PATH"),
        "nuclei": (bool(nuclei), nuclei or "Nuclei executable not found on PATH"),
        "ffuf": (bool(ffuf), ffuf or "ffuf executable not found on PATH"),
        "sqlmap": (bool(sqlmap), sqlmap or "sqlmap executable not found on PATH"),
    }


def _check_url(target: str) -> None:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ScannerError("Web scanner target must be an http(s) URL without embedded credentials.")


def validate_web_target(target: str) -> str:
    """Validate and return a normalized URL accepted by the web adapters."""
    value = target.strip()
    try:
        _check_url(value)
        parsed = urlparse(value)
        _ = parsed.port
    except ValueError as exc:
        raise ScannerError(f"Invalid web scanner target URL: {exc}") from exc
    if any(character.isspace() for character in value) or any(ord(character) < 32 for character in value):
        raise ScannerError("Web scanner target cannot contain spaces or control characters.")
    return value


def normalize_burp_seed(target: str) -> str:
    """Validate a single absolute Burp seed and canonicalize its origin/path."""
    value = target.strip()
    try:
        parsed = urlparse(value)
        port = parsed.port  # access validates malformed/out-of-range ports
    except ValueError as exc:
        raise ScannerError(f"Invalid Burp seed URL: {exc}") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ScannerError("Burp seed must be an absolute http(s) URL, such as https://example.com/.")
    if any(character.isspace() for character in value) or any(ord(character) < 32 for character in value):
        raise ScannerError("Burp seed URL cannot contain spaces or control characters. URL-encode spaces in paths.")
    if parsed.fragment:
        raise ScannerError("Burp seed URLs with # fragments are not supported by this scanner setup. Enter the page URL without the fragment.")
    host = parsed.hostname.encode("idna").decode("ascii")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host + (f":{port}" if port is not None else "")
    path = parsed.path or "/"
    return urlunparse((parsed.scheme.lower(), netloc, path, parsed.params, parsed.query, ""))


def _run(args: list[str], *, timeout: int, allow_nonzero: bool = False) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise ScannerError(f"Scanner executable not found: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"Scan timed out after {timeout} seconds.") from exc
    if completed.returncode != 0 and not allow_nonzero:
        detail = (completed.stderr or completed.stdout or "No scanner error details were returned.").strip()
        raise ScannerError(detail[-2500:])
    return completed


def _burp_request(base_url: str, api_key: str, route: str, *, payload: dict[str, object] | None = None,
                  timeout: int = 30, include_headers: bool = False) -> object:
    """Call the Burp Suite Professional REST API (API key is a URL path segment)."""
    url = f"{base_url.rstrip('/')}/{quote(api_key, safe='')}/v0.1/{route.lstrip('/')}"
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(url, data=body, headers={"Accept": "application/json", "Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(20 * 1024 * 1024 + 1)
            response_headers = dict(response.headers.items())
    except HTTPError as exc:
        detail = exc.read(2000).decode("utf-8", "replace")
        raise ScannerError(f"Burp API returned HTTP {exc.code}: {detail or exc.reason}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ScannerError(f"Could not reach Burp REST API at {base_url}: {exc}") from exc
    if len(raw) > 20 * 1024 * 1024:
        raise ScannerError("Burp API response exceeded the 20 MB safety limit.")
    if not raw:
        if include_headers:
            return {"_response_body": {}, "_response_headers": response_headers}
        return {}
    try:
        result = json.loads(raw)
        if include_headers:
            return {"_response_body": result, "_response_headers": response_headers}
        return result
    except json.JSONDecodeError as exc:
        raise ScannerError("Burp API returned an unexpected response. Check the API base URL and key.") from exc


def _burp_issue_findings(issues_response: object, *, target: str, job_id: str) -> list[Finding]:
    """Normalize Burp REST API issue objects into the shared finding format."""
    if isinstance(issues_response, dict):
        issues = issues_response.get("issues", [])
    elif isinstance(issues_response, list):
        issues = issues_response
    else:
        issues = []
    if not isinstance(issues, list):
        raise ScannerError("Burp API issue response did not contain an issues list.")

    findings: list[Finding] = []
    for index, issue in enumerate(issues):
        if not isinstance(issue, dict):
            continue
        issue_type = issue.get("issue_type", {})
        title = issue_type.get("name", "Burp issue") if isinstance(issue_type, dict) else str(issue_type or "Burp issue")
        origin = str(issue.get("origin") or "")
        issue_path = str(issue.get("path") or "")
        url = str(issue.get("url") or (origin.rstrip("/") + "/" + issue_path.lstrip("/") if origin and issue_path else origin or issue_path or target))
        parsed = urlparse(url)
        severity = str(issue.get("severity", "unknown")).casefold()
        if severity in {"information", "informational"}:
            severity = "info"
        if severity not in {"info", "low", "medium", "high", "critical", "unknown"}:
            severity = "unknown"
        description = str(issue.get("issueDetail") or issue.get("description") or issue.get("issueBackground") or (issue_type.get("description") if isinstance(issue_type, dict) else "") or "")
        remediation = str(issue.get("remediationDetail") or issue.get("remediation") or issue.get("remediationBackground") or (issue_type.get("remediation") if isinstance(issue_type, dict) else "") or "")
        evidence_parts = [part for part in (description, f"Remediation: {remediation}" if remediation else "") if part]
        findings.append(Finding(
            id=f"{job_id}:burp:{index}", source_tool="burp", target=target,
            host=parsed.hostname or target, port=parsed.port,
            protocol=parsed.scheme or None, title=str(title)[:240], description=description,
            severity=severity, cve_ids=_cves(f"{title} {description}"), evidence="\n".join(evidence_parts)[:20000],
            raw_ref=job_id, timestamp=datetime.now(timezone.utc),
        ))
    return findings


def _run_burp_scan(target: str, *, raw_dir: Path, job_id: str, api_url: str, api_key: str,
                   profile: str = "", on_progress: Callable[[str], None] | None = None,
                   timeout: int = 7200) -> tuple[list[Finding], Path, str]:
    """Start and monitor a Burp scan, then persist the API's raw issue response."""
    target = normalize_burp_seed(target)
    parsed_api = urlparse(api_url)
    if parsed_api.scheme not in {"http", "https"} or not parsed_api.hostname or parsed_api.username or parsed_api.password:
        raise ScannerError("Burp REST API URL must be an http(s) URL without embedded credentials.")
    if not api_key.strip():
        raise ScannerError("Enter the API key configured in Burp Suite REST API settings.")
    scan_request: dict[str, object] = {"urls": [target]}
    # Named scan configurations are installation-specific. Omit this field by
    # default so Burp uses its own configured default instead of a guessed name.
    if profile.strip():
        scan_request["scan_configurations"] = [{"name": profile.strip(), "type": "NamedConfiguration"}]
    start_response = _burp_request(
        api_url, api_key.strip(), "scan", payload=scan_request, include_headers=True,
    )
    started = start_response.get("_response_body") if isinstance(start_response, dict) else start_response
    response_headers = start_response.get("_response_headers", {}) if isinstance(start_response, dict) else {}
    task_id = None
    if isinstance(started, dict):
        task_id = started.get("task_id") or started.get("taskId") or started.get("scan_id") or started.get("id")
    if not task_id and isinstance(response_headers, dict):
        location = str(response_headers.get("Location") or response_headers.get("location") or "")
        if location:
            task_id = urlparse(location).path.rstrip("/").split("/")[-1]
    if not task_id:
        raise ScannerError("Burp did not return a scan task ID. Check the REST API documentation for this Burp version.")
    if on_progress:
        on_progress(f"Burp accepted scan {task_id} · {profile.strip() or 'Burp default configuration'}")

    deadline = time.monotonic() + timeout
    status: object = {}
    last_progress: object = None
    while time.monotonic() < deadline:
        status = _burp_request(api_url, api_key.strip(), f"scan/{quote(str(task_id), safe='')}", timeout=60)
        if not isinstance(status, dict):
            raise ScannerError("Burp returned an invalid scan status response.")
        state = str(status.get("scan_status") or status.get("status") or "").casefold()
        metrics = status.get("scan_metrics") if isinstance(status.get("scan_metrics"), dict) else {}
        progress = metrics.get("crawl_and_audit_progress")
        if on_progress and progress is not None and progress != last_progress:
            on_progress(f"Burp scan {task_id} · crawl and audit {progress}%")
            last_progress = progress
        if state in {"failed", "cancelled", "canceled", "aborted", "paused"}:
            detail = ""
            for field in ("error", "message", "scan_errors", "errors", "scan_message"):
                value = status.get(field)
                if value:
                    detail = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
                    break
            if state == "paused" and (not detail or "seed" in detail.casefold()):
                detail = (detail + " " if detail else "") + (
                    "Burp could not connect to any seed URLs. Verify DNS resolution, outbound network access, "
                    "TLS/certificate trust, and redirects from the machine running Burp. If the site redirects "
                    "to another hostname, use that final URL and include it in the authorized scan scope."
                )
            raise ScannerError(f"Burp scan {task_id} ended with status: {state}. {detail}".strip())
        if state in {"succeeded", "completed", "complete", "finished"} or str(progress) == "100":
            break
        time.sleep(3)
    else:
        raise ScannerError(f"Burp scan {task_id} exceeded the {timeout // 60}-minute time limit.")

    try:
        issues = _burp_request(api_url, api_key.strip(), f"scan/{quote(str(task_id), safe='')}/issues", timeout=90)
    except ScannerError as exc:
        # Some Burp API builds include issue objects in the task status response.
        if isinstance(status, dict) and isinstance(status.get("issues"), (list, dict)):
            issues = status["issues"]
        elif isinstance(status, dict) and isinstance(status.get("issue_events"), (list, dict)):
            issues = status["issue_events"]
        else:
            raise ScannerError(f"Burp scan completed, but issue retrieval failed: {exc}") from exc
    raw_path = raw_dir / f"{job_id}-burp.json"
    raw_path.write_text(json.dumps({"task_id": task_id, "status": status, "issues": issues}, indent=2), encoding="utf-8")
    findings = _burp_issue_findings(issues, target=target, job_id=job_id)
    return findings, raw_path, str(task_id)


def _web_finding(scanner: str, target: str, job_id: str, index: int, *, title: str,
                 description: str = "", severity: str = "unknown", evidence: str = "",
                 location: str = "") -> Finding:
    parsed = urlparse(location or target)
    severity = severity.lower()
    if severity in {"informational", "information"}:
        severity = "info"
    if severity not in {"info", "low", "medium", "high", "critical", "unknown"}:
        severity = "unknown"
    return Finding(
        id=f"{job_id}:{scanner}:{index}", source_tool=scanner, target=target,
        host=parsed.hostname or urlparse(target).hostname or target,
        port=parsed.port or (443 if parsed.scheme == "https" else 80),
        protocol=parsed.scheme or urlparse(target).scheme or None,
        title=title[:240], description=description[:6000], severity=severity,
        cve_ids=_cves(f"{title} {description} {evidence}"), evidence=evidence[:20000],
        raw_ref=job_id, timestamp=datetime.now(timezone.utc), service_name=location or None,
    )


def _parse_nuclei(path: Path, target: str, job_id: str) -> list[Finding]:
    findings = []
    for index, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") or {}
        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or classification.get("cve") or []
        title = str(info.get("name") or item.get("template-id") or "Nuclei finding")
        description = str(info.get("description") or "")
        finding = _web_finding("nuclei", target, job_id, index, title=title,
                               description=description, severity=str(info.get("severity", "unknown")),
                               evidence=json.dumps(item, ensure_ascii=False), location=str(item.get("matched-at") or item.get("host") or target))
        finding.cve_ids = sorted(set(finding.cve_ids + [str(value) for value in (cves if isinstance(cves, list) else [cves])]))
        findings.append(finding)
    return findings


def _parse_ffuf(path: Path, target: str, job_id: str) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("results", []) if isinstance(data, dict) else []
    findings = []
    for index, item in enumerate(rows):
        url = str(item.get("url") or target)
        status = item.get("status", "unknown")
        finding = _web_finding("ffuf", target, job_id, index,
                               title=f"Content discovered: {url}",
                               description=f"ffuf received HTTP status {status}; review the resource manually.",
                               severity="info", evidence=json.dumps(item, ensure_ascii=False), location=url)
        findings.append(finding)
    return findings


def _parse_zap(path: Path, target: str, job_id: str) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    sites = data.get("site", []) if isinstance(data, dict) else []
    findings = []
    for site in sites:
        for alert in site.get("alerts", []):
            instances = alert.get("instances") or [{}]
            for instance in instances:
                index = len(findings)
                findings.append(_web_finding(
                    "zap", target, job_id, index, title=str(alert.get("name") or "ZAP alert"),
                    description=str(alert.get("desc") or alert.get("description") or ""),
                    severity={"3": "high", "2": "medium", "1": "low", "0": "info"}.get(str(alert.get("riskcode")), "unknown"),
                    evidence="\n".join(str(instance.get(key, "")) for key in ("uri", "method", "evidence", "attack", "other") if instance.get(key)),
                    location=str(instance.get("uri") or site.get("@name") or target),
                ))
    return findings


def _free_local_port() -> int:
    """Reserve an available loopback port number for a one-shot ZAP process."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run_scan(
    scanner: str,
    target: str,
    *,
    scan_type: str = "quick",
    ports: str = "",
    wordlist: str = "",
    burp_api_url: str = "http://127.0.0.1:1337",
    burp_api_key: str = "",
    burp_profile: str = "",
    nmap_options: dict[str, object] | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> tuple[list[dict[str, object]], str]:
    """Execute one scan and return normalized findings plus the raw-output path."""
    if scanner not in SCANNERS:
        raise ScannerError(f"Unknown scanner: {scanner}")
    job_id = str(uuid.uuid4())
    raw_dir = data_dir() / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    if scanner == "burp":
        findings, raw_path, _task_id = _run_burp_scan(
            target, raw_dir=raw_dir, job_id=job_id, api_url=burp_api_url,
            api_key=burp_api_key, profile=burp_profile, on_progress=on_progress,
        )
        return [finding.to_dict() for finding in findings], raw_path.relative_to(data_dir()).as_posix()

    if scanner == "nmap":
        executable = shutil.which("nmap")
        if not executable:
            raise ScannerError("Nmap executable was not found on PATH.")
        if not target or target.startswith("-") or re.search(r"\s", target):
            raise ScannerError("Enter one hostname or IP address for Nmap.")
        if scan_type not in {"quick", "version"}:
            raise ScannerError("Choose the quick or version profile.")
        if ports and not re.fullmatch(r"[0-9,-]+", ports):
            raise ScannerError("Ports may contain only digits, commas, and hyphens.")
        raw_path = raw_dir / f"{job_id}-nmap.xml"
        args = [executable, "-oX", str(raw_path)]
        options = nmap_options or {}
        timing = str(options.get("timing", "T3"))
        if timing not in {"T0", "T1", "T2", "T3", "T4", "T5"}:
            raise ScannerError("Nmap timing must be between T0 and T5.")
        args += [f"-{timing}"]
        args += ["-F"] if scan_type == "quick" else ["--top-ports", "100"]
        if scan_type == "version":
            args.append("-sV")
        allowed_nmap_flags = {
            "service_version": "-sV", "os_detection": "-O", "default_scripts": "-sC",
            "udp_scan": "-sU", "skip_host_discovery": "-Pn", "open_only": "--open",
            "tcp_connect": "-sT", "syn_scan": "-sS",
        }
        requested_flags = options.get("flags", [])
        if not isinstance(requested_flags, list) or any(flag not in allowed_nmap_flags for flag in requested_flags):
            raise ScannerError("Nmap options include an unsupported flag.")
        if "tcp_connect" in requested_flags and "syn_scan" in requested_flags:
            raise ScannerError("Choose either TCP connect or SYN scan, not both.")
        for flag in requested_flags:
            value = allowed_nmap_flags[flag]
            if value not in args:
                args.append(value)
        if ports:
            args += ["-p", ports]
        args.append(target)
        _run(args, timeout=900)
        findings = parse_nmap_xml(raw_path, target=target, job_id=job_id)
    elif scanner == "nikto":
        _check_url(target)
        command = _nikto_command()
        if not command:
            raise ScannerError("Nikto was not found. Install Nikto and Perl, or set NIKTO_SCRIPT to nikto.pl.")
        raw_path = raw_dir / f"{job_id}-nikto.json"
        args = command + ["-h", target, "-output", str(raw_path), "-Format", "json", "-maxtime", "5m", "-timeout", "10", "-nointeractive", "-nocheck"]
        completed = _run(args, timeout=360, allow_nonzero=True)
        console_output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
        log_path = raw_dir / f"{job_id}-nikto.log"
        if console_output:
            log_path.write_text(console_output + "\n", encoding="utf-8", errors="replace")
        findings: list[Finding] = []
        output_error = ""
        json_parsed = False
        if raw_path.is_file() and raw_path.stat().st_size:
            try:
                findings = parse_nikto_json(raw_path, target=target, job_id=job_id)
                json_parsed = True
            except (OSError, ValueError) as exc:
                output_error = str(exc)
        if not findings and console_output:
            findings = parse_nikto_text(console_output, target=target, job_id=job_id)
            if findings:
                raw_path = log_path
        if completed.returncode != 0 and not findings:
            detail = console_output[-2500:] or f"Nikto exited with code {completed.returncode}."
            if output_error:
                detail = f"{detail}\nCould not use the Nikto JSON report: {output_error}"
            raise ScannerError(f"Nikto exited with code {completed.returncode} and returned no parseable findings. {detail}")
        if not findings and not json_parsed:
            detail = f" Could not parse the Nikto JSON report: {output_error}" if output_error else ""
            raise ScannerError(f"Nikto did not return parseable scan results.{detail}")
        if not raw_path.is_file() or not raw_path.stat().st_size:
            if not log_path.is_file():
                raise ScannerError("Nikto completed without producing a JSON report or console output.")
            raw_path = log_path
    elif scanner == "gobuster":
        _check_url(target)
        executable = shutil.which("gobuster")
        if not executable:
            raise ScannerError("Gobuster executable was not found on PATH.")
        wordlist_path = Path(wordlist).expanduser()
        if not wordlist_path.is_file():
            raise ScannerError("Choose an existing local wordlist file for Gobuster.")
        raw_path = raw_dir / f"{job_id}-gobuster.txt"
        args = [executable, "dir", "-u", target, "-w", str(wordlist_path.resolve()), "-t", "10", "-q", "-o", str(raw_path)]
        _run(args, timeout=1800)
        findings = parse_gobuster_text(raw_path, target=target, job_id=job_id)
    elif scanner == "nuclei":
        _check_url(target)
        executable = shutil.which("nuclei")
        if not executable:
            raise ScannerError("Nuclei executable was not found on PATH.")
        raw_path = raw_dir / f"{job_id}-nuclei.jsonl"
        args = [executable, "-u", target, "-jsonl", "-o", str(raw_path), "-rl", "10", "-timeout", "5", "-retries", "1", "-no-color"]
        _run(args, timeout=1800)
        findings = _parse_nuclei(raw_path, target, job_id)
    elif scanner == "ffuf":
        _check_url(target)
        executable = shutil.which("ffuf")
        if not executable:
            raise ScannerError("ffuf executable was not found on PATH.")
        wordlist_path = Path(wordlist).expanduser()
        if not wordlist_path.is_file():
            raise ScannerError("Choose an existing local wordlist file for ffuf.")
        raw_path = raw_dir / f"{job_id}-ffuf.json"
        fuzz_url = target.rstrip("/") + "/FUZZ"
        args = [executable, "-u", fuzz_url, "-w", str(wordlist_path.resolve()), "-of", "json", "-o", str(raw_path), "-rate", "10", "-t", "10", "-maxtime", "1800", "-noninteractive"]
        _run(args, timeout=1900)
        findings = _parse_ffuf(raw_path, target, job_id)
    elif scanner == "zap":
        _check_url(target)
        executable = shutil.which("zaproxy") or shutil.which("zap.sh") or shutil.which("zap.bat")
        if not executable:
            raise ScannerError("OWASP ZAP executable was not found on PATH.")
        raw_path = raw_dir / f"{job_id}-zap.json"
        proxy_port = _free_local_port()
        completed = _run([executable, "-cmd", "-silent", "-port", str(proxy_port), "-quickurl", target, "-quickout", str(raw_path)], timeout=3600, allow_nonzero=True)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "No output from ZAP.").strip()
            raise ScannerError(f"ZAP exited with code {completed.returncode} using proxy port {proxy_port}: {detail[-2500:]}")
        if not raw_path.is_file():
            detail = (completed.stderr or completed.stdout or "ZAP exited without creating its JSON report.").strip()
            if "address already in use" in detail.casefold():
                detail += " The chosen local proxy port was occupied; close the competing proxy and retry."
            raise ScannerError(f"ZAP produced no report on proxy port {proxy_port}: {detail[-2500:]}")
        findings = _parse_zap(raw_path, target, job_id)
    elif scanner == "sqlmap":
        _check_url(target)
        executable = shutil.which("sqlmap") or shutil.which("sqlmap.py")
        if not executable:
            raise ScannerError("sqlmap executable was not found on PATH.")
        output_dir = raw_dir / f"{job_id}-sqlmap"
        completed = _run([executable, "-u", target, "--batch", "--smart", "--risk=1", "--level=1", "--crawl=1", "--output-dir", str(output_dir)], timeout=3600, allow_nonzero=True)
        raw_path = raw_dir / f"{job_id}-sqlmap.txt"
        output = (completed.stdout or "") + "\n" + (completed.stderr or "")
        raw_path.write_text(output, encoding="utf-8", errors="replace")
        if completed.returncode != 0 and "sqlmap identified the following injection point" not in output.lower():
            raise ScannerError(f"sqlmap exited with code {completed.returncode}: {output[-2000:]}")
        findings = []
        marker = "sqlmap identified the following injection point"
        if marker in output.lower():
            findings.append(_web_finding("sqlmap", target, job_id, 0,
                                         title="Potential SQL injection confirmed by sqlmap",
                                         description="sqlmap reported an injection point. Validate the parameter and impact from the complete raw output.",
                                         severity="high", evidence=output[-20000:], location=target))
    return [finding.to_dict() for finding in findings], raw_path.relative_to(data_dir()).as_posix()
