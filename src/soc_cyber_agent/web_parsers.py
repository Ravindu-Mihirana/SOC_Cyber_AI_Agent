"""Normalize Nikto JSON and Gobuster text output into shared findings."""

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .models import Finding, utc_now

_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_GOBUSTER_PATTERN = re.compile(r"^(.+?)\s+\(Status:\s*(\d{3})\)(.*)$")


def _web_location(target: str, location: str) -> tuple[str, int | None, str | None]:
    parsed = urlparse(target)
    host = parsed.hostname or target
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        port = None
    return host, port, parsed.scheme or None


def parse_nikto_json(path: str | Path, *, target: str, job_id: str) -> list[Finding]:
    """Parse Nikto JSON findings; leave severity unknown unless supplied."""
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    host, port, protocol = _web_location(target, "")
    vulnerabilities = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    findings: list[Finding] = []
    for index, item in enumerate(vulnerabilities):
        if not isinstance(item, dict):
            continue
        message = str(item.get("msg") or item.get("message") or item.get("description") or "Nikto reported a web server issue.")
        path_ref = str(item.get("url") or item.get("OSVDB") or "")
        title = message.strip().splitlines()[0][:180] or "Nikto web finding"
        severity_value = str(item.get("severity", "unknown")).lower()
        severity = severity_value if severity_value in {"info", "low", "medium", "high", "critical"} else "unknown"
        evidence = json.dumps(item, ensure_ascii=False, sort_keys=True)
        findings.append(Finding(
            id=f"{job_id}:nikto:{index}", source_tool="nikto", target=target,
            host=host, port=port, protocol=protocol, title=title,
            description=message, severity=severity, cve_ids=sorted(set(_CVE_PATTERN.findall(evidence))),
            evidence=evidence, raw_ref=job_id, timestamp=utc_now(),
            status="open", service_name=path_ref or None,
        ))
    return findings


def parse_gobuster_text(path: str | Path, *, target: str, job_id: str) -> list[Finding]:
    """Parse quiet Gobuster directory output into informational findings."""
    host, port, protocol = _web_location(target, "")
    findings: list[Finding] = []
    for index, line in enumerate(Path(path).read_text(encoding="utf-8", errors="replace").splitlines()):
        match = _GOBUSTER_PATTERN.match(line.strip())
        if not match:
            continue
        discovered_path, status_code, remainder = match.groups()
        findings.append(Finding(
            id=f"{job_id}:gobuster:{index}", source_tool="gobuster", target=target,
            host=host, port=port, protocol=protocol,
            title=f"Web path discovered: {discovered_path}",
            description=f"Gobuster received HTTP status {status_code} for this path; review it manually.",
            severity="info", cve_ids=[], evidence=f"HTTP {status_code} {remainder.strip()}".strip(),
            raw_ref=job_id, timestamp=utc_now(), service_name=discovered_path,
        ))
    return findings
