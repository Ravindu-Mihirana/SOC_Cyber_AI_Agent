"""Parse Nmap XML output into the shared Finding schema."""

from pathlib import Path
from xml.etree import ElementTree

from .models import Finding, utc_now


def parse_nmap_xml(xml_path: str | Path, *, target: str, job_id: str) -> list[Finding]:
    """Return one informational finding per open port in an Nmap XML file."""
    root = ElementTree.parse(xml_path).getroot()
    findings: list[Finding] = []

    for host in root.findall("host"):
        address = host.find("address")
        host_address = address.get("addr", target) if address is not None else target
        for port_node in host.findall("ports/port"):
            state = port_node.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port_node.find("service")
            service_name = service.get("name", "unknown") if service is not None else "unknown"
            product = service.get("product") if service is not None else None
            version = service.get("version") if service is not None else None
            method = service.get("method") if service is not None else None
            confidence_text = service.get("conf") if service is not None else None
            confidence = int(confidence_text) if confidence_text and confidence_text.isdigit() else None
            identified = bool(product or version)
            service_label = " ".join(value for value in (product, version) if value)
            evidence = (
                f"Identified service: {service_label}"
                if identified else
                f"Port-based service guess: {service_name} (method={method or 'unknown'}, confidence={confidence if confidence is not None else 'unknown'}/10)."
            )
            port_id = int(port_node.get("portid", "0"))
            protocol = port_node.get("protocol", "unknown")
            findings.append(Finding(
                id=f"{job_id}:{host_address}:{protocol}:{port_id}",
                source_tool="nmap",
                target=target,
                host=host_address,
                port=port_id,
                protocol=protocol,
                title=f"Open port {port_id}/{protocol} ({service_name})",
                description=(
                    f"Nmap reported this port as open and identified {service_label}."
                    if identified else
                    f"Nmap reported this port as open. The service label '{service_name}' is a port-based guess, not a confirmed product/version."
                ),
                severity="info",
                cve_ids=[],
                evidence=evidence,
                raw_ref=job_id,
                timestamp=utc_now(),
                service_name=service_name,
                service_product=product,
                service_version=version,
                service_detection_method=method,
                service_confidence=confidence,
            ))
    return findings
