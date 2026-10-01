"""Direct scanner adapters shared by the UI; all invocations avoid a shell."""

import os
import re
import shutil
import subprocess
import uuid
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

from .models import Finding
from .nmap_parser import parse_nmap_xml
from .report_importers import _cves
from .storage import data_dir
from .web_parsers import parse_gobuster_text, parse_nikto_json

SCANNERS = ("nmap", "burp", "nikto", "gobuster")


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
    return {
        "nmap": (bool(nmap), nmap or "Nmap executable not found on PATH"),
        "burp": (burp_configured, os.environ.get("BURP_API_URL", "Configure Burp REST API URL and key in the assessment form")),
        "nikto": (bool(nikto), " ".join(nikto) if nikto else "Install Nikto and Perl; set NIKTO_SCRIPT if using nikto.pl"),
        "gobuster": (bool(gobuster), gobuster or "Gobuster executable not found on PATH"),
    }


def _check_url(target: str) -> None:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ScannerError("Web scanner target must be an http(s) URL without embedded credentials.")


def _run(args: list[str], *, timeout: int) -> None:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise ScannerError(f"Scanner executable not found: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"Scan timed out after {timeout} seconds.") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "No scanner error details were returned.").strip()
        raise ScannerError(detail[-2500:])


def _burp_request(base_url: str, api_key: str, route: str, *, payload: dict[str, object] | None = None,
                  timeout: int = 30) -> object:
    """Call the Burp Suite Professional REST API (API key is a URL path segment)."""
    url = f"{base_url.rstrip('/')}/{quote(api_key, safe='')}/v0.1/{route.lstrip('/')}"
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(url, data=body, headers={"Accept": "application/json", "Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(20 * 1024 * 1024 + 1)
    except HTTPError as exc:
        detail = exc.read(2000).decode("utf-8", "replace")
        raise ScannerError(f"Burp API returned HTTP {exc.code}: {detail or exc.reason}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ScannerError(f"Could not reach Burp REST API at {base_url}: {exc}") from exc
    if len(raw) > 20 * 1024 * 1024:
        raise ScannerError("Burp API response exceeded the 20 MB safety limit.")
    if not raw:
        return {}
    try:
        return json.loads(raw)
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
                   profile: str, on_progress: Callable[[str], None] | None = None,
                   timeout: int = 7200) -> tuple[list[Finding], Path, str]:
    """Start and monitor a Burp scan, then persist the API's raw issue response."""
    _check_url(target)
    parsed_api = urlparse(api_url)
    if parsed_api.scheme not in {"http", "https"} or not parsed_api.hostname or parsed_api.username or parsed_api.password:
        raise ScannerError("Burp REST API URL must be an http(s) URL without embedded credentials.")
    if not api_key.strip():
        raise ScannerError("Enter the API key configured in Burp Suite REST API settings.")
    allowed_profiles = {"Crawl strategy - fastest", "Audit checks - light active", "Audit checks - all issues"}
    if profile not in allowed_profiles:
        raise ScannerError("Choose a supported Burp scan profile.")

    started = _burp_request(api_url, api_key.strip(), "scan", payload={
        "urls": [target],
        "scan_configurations": [{"name": profile, "type": "NamedConfiguration"}],
    })
    task_id = (started.get("task_id") or started.get("scan_id")) if isinstance(started, dict) else None
    if not task_id:
        raise ScannerError("Burp did not return a scan task ID. Check the REST API documentation for this Burp version.")
    if on_progress:
        on_progress(f"Burp accepted scan {task_id} · {profile}")

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
        if state in {"failed", "cancelled", "canceled", "aborted"}:
            raise ScannerError(f"Burp scan {task_id} ended with status: {state}.")
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


def run_scan(
    scanner: str,
    target: str,
    *,
    scan_type: str = "quick",
    ports: str = "",
    wordlist: str = "",
    burp_api_url: str = "http://127.0.0.1:1337",
    burp_api_key: str = "",
    burp_profile: str = "Crawl strategy - fastest",
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
        args += ["-T3", "-F"] if scan_type == "quick" else ["-T3", "-sV", "--top-ports", "100"]
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
        _run(args, timeout=360)
        findings = parse_nikto_json(raw_path, target=target, job_id=job_id)
    else:
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
    return [finding.to_dict() for finding in findings], raw_path.relative_to(data_dir()).as_posix()
