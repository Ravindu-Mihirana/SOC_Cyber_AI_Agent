"""Import scanner report exports into the shared finding format."""

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import urlparse
from uuid import uuid4

from .models import Finding

MAX_REPORT_BYTES = 50 * 1024 * 1024


class ReportImportError(ValueError):
    pass


def _text(node: ET.Element, name: str, default: str = "") -> str:
    found = node.find(name)
    return (found.text or "").strip() if found is not None else default


def _severity(value: str, cvss: str = "") -> str:
    value = value.strip().lower()
    if value in {"critical", "high", "medium", "low", "info", "information", "informational"}:
        return "info" if value in {"information", "informational"} else value
    try:
        score = float(cvss)
    except (TypeError, ValueError):
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _cves(text: str) -> list[str]:
    return sorted({item.upper() for item in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, re.I)})


def _finding(source: str, target: str, host: str, port: int | None, protocol: str | None,
             title: str, description: str, severity: str, evidence: str, raw_ref: str,
             cves: list[str] | None = None, index: int = 0) -> Finding:
    job_id = raw_ref
    return Finding(
        id=f"{job_id}:{source}:{index}", source_tool=source, target=target or host,
        host=host or target, port=port, protocol=protocol, title=title[:240] or "Scanner finding",
        description=description, severity=_severity(severity), cve_ids=cves or _cves(title + " " + description + " " + evidence),
        evidence=evidence[:20000], raw_ref=raw_ref,
        timestamp=datetime.now(timezone.utc), status="open",
    )


def parse_burp_xml(content: bytes, *, raw_ref: str) -> list[Finding]:
    """Parse Burp Suite XML issue report export."""
    root = _parse_xml(content)
    issues = root.findall(".//issue")
    if not issues:
        raise ReportImportError("No <issue> records were found. Export a Burp XML issues report.")
    results: list[Finding] = []
    for index, issue in enumerate(issues):
        host_node = issue.find("host")
        host_text = (host_node.text or "").strip() if host_node is not None else ""
        target = host_text or _text(issue, "host", "unknown")
        parsed_target = urlparse(target)
        host = (host_node.get("ip") if host_node is not None else None) or parsed_target.hostname or target
        port = None
        protocol = None
        if host_node is not None:
            try:
                port = int(host_node.get("port", "")) or None
            except ValueError:
                pass
            protocol = host_node.get("protocol")
        detail = _text(issue, "issueDetail") or _text(issue, "issueBackground")
        remediation = _text(issue, "remediationDetail") or _text(issue, "remediationBackground")
        evidence = "\n".join(value for value in (detail, "Remediation: " + remediation if remediation else "") if value)
        name = _text(issue, "name", "Burp issue")
        if not protocol:
            protocol = parsed_target.scheme or None
        results.append(_finding(
            "burp", target, host, port, protocol, name, detail or _text(issue, "issueBackground"),
            _text(issue, "severity", "unknown"), evidence, raw_ref,
            _cves(name + " " + detail), index,
        ))
    return results


def parse_openvas_xml(content: bytes, *, raw_ref: str) -> list[Finding]:
    """Parse an OpenVAS/GVM XML report containing <result> records."""
    root = _parse_xml(content)
    results_nodes = root.findall(".//result")
    if not results_nodes:
        raise ReportImportError("No <result> records were found. Export an OpenVAS/GVM XML report.")
    findings: list[Finding] = []
    targets: set[str] = set()
    for index, result in enumerate(results_nodes):
        host = _text(result, "host", "unknown")
        targets.add(host)
        port_text = _text(result, "port")
        match = re.fullmatch(r"(\d+)/(tcp|udp)", port_text, re.I)
        port = int(match.group(1)) if match else None
        protocol = match.group(2).lower() if match else None
        nvt = result.find("nvt")
        cvss = _text(nvt, "cvss_base") if nvt is not None else ""
        threat = _text(result, "threat", "unknown")
        description = _text(result, "description")
        oid = nvt.get("oid", "") if nvt is not None else ""
        cves = []
        if nvt is not None:
            cves.extend((item.text or "").strip() for item in nvt.findall("cve"))
        cves = sorted({cve.upper() for cve in cves if cve and cve.upper() != "NOCVE"})
        title = _text(nvt, "name") if nvt is not None else ""
        if not title:
            title = _text(result, "name", "OpenVAS finding")
        evidence = "\n".join(filter(None, [f"Threat: {threat}", f"CVSS: {cvss}" if cvss else "", f"NVT OID: {oid}" if oid else "", description]))
        findings.append(_finding(
            "openvas", host, host, port, protocol, title, description, _severity(threat, cvss),
            evidence, raw_ref, cves, index,
        ))
    for finding in findings:
        finding.target = ", ".join(sorted(targets))
    return findings


def _parse_xml(content: bytes) -> ET.Element:
    if not content:
        raise ReportImportError("The uploaded report is empty.")
    if len(content) > MAX_REPORT_BYTES:
        raise ReportImportError("Report exceeds the 50 MB import limit.")
    try:
        return ET.fromstring(content)
    except ET.ParseError as exc:
        raise ReportImportError(f"Could not parse the XML report: {exc}") from exc


def new_import_id() -> str:
    return str(uuid4())
