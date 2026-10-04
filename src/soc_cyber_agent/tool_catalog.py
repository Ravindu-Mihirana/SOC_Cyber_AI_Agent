"""Dashboard catalog and readiness checks for integrated and optional tools."""

import shutil
from typing import Any


TOOL_CATEGORIES: tuple[dict[str, Any], ...] = (
    {
        "name": "Web and API scanning",
        "tools": (
            {"name": "OWASP ZAP", "summary": "DAST, API import, spidering, and active/passive web checks.", "url": "https://www.zaproxy.org/docs/automate/automation-framework/", "binaries": ("zap.sh", "zap.bat", "zaproxy")},
            {"name": "Nuclei", "summary": "Template-based checks for web, API, network, DNS, and cloud findings.", "url": "https://docs.projectdiscovery.io/tools/nuclei/overview", "binaries": ("nuclei",)},
            {"name": "ffuf", "summary": "Web content, virtual-host, and parameter discovery.", "url": "https://github.com/ffuf/ffuf", "binaries": ("ffuf",)},
            {"name": "testssl.sh", "summary": "TLS versions, ciphers, certificates, and common TLS weaknesses.", "url": "https://github.com/testssl/testssl.sh", "binaries": ("testssl.sh", "testssl")},
            {"name": "sqlmap", "summary": "Focused SQL injection testing for authorized applications.", "url": "https://github.com/sqlmapproject/sqlmap", "binaries": ("sqlmap",)},
            {"name": "Nmap", "summary": "Host, port, and optional service-version discovery.", "integration": "nmap"},
            {"name": "Burp Suite", "summary": "Web crawl and audit through Burp's REST API.", "integration": "burp"},
            {"name": "Nikto", "summary": "Web-server configuration and known-file checks.", "integration": "nikto"},
            {"name": "Gobuster", "summary": "Directory and path discovery with a local wordlist.", "integration": "gobuster"},
            {"name": "OpenVAS / Greenbone", "summary": "Import completed Greenbone XML assessment reports.", "integration": "openvas"},
        ),
    },
    {
        "name": "Code and dependencies",
        "tools": (
            {"name": "Semgrep", "summary": "Static application security checks and code rules.", "url": "https://semgrep.dev/docs/", "binaries": ("semgrep",)},
            {"name": "Gitleaks", "summary": "Secrets detection in files and Git history.", "url": "https://github.com/gitleaks/gitleaks", "binaries": ("gitleaks",)},
            {"name": "Trivy", "summary": "Repository, dependency, secret, image, and misconfiguration scans.", "url": "https://trivy.dev/docs/latest/", "binaries": ("trivy",)},
            {"name": "Syft", "summary": "Software bill of materials generation for filesystems and images.", "url": "https://github.com/anchore/syft", "binaries": ("syft",)},
            {"name": "Grype", "summary": "Known-vulnerability scans of images, filesystems, and SBOMs.", "url": "https://github.com/anchore/grype", "binaries": ("grype",)},
            {"name": "Checkov", "summary": "Infrastructure-as-code and software supply-chain checks.", "url": "https://github.com/bridgecrewio/checkov", "binaries": ("checkov",)},
        ),
    },
    {
        "name": "Cloud and infrastructure",
        "tools": (
            {"name": "Prowler", "summary": "Cloud security posture and benchmark checks across cloud accounts.", "url": "https://prowler.com/prowler-oss", "binaries": ("prowler",)},
            {"name": "Checkov", "summary": "Terraform, Kubernetes, and other infrastructure-as-code checks.", "url": "https://github.com/bridgecrewio/checkov", "binaries": ("checkov",)},
            {"name": "kube-bench", "summary": "Kubernetes configuration checks against CIS benchmarks.", "url": "https://github.com/aquasecurity/kube-bench", "binaries": ("kube-bench",)},
            {"name": "Trivy", "summary": "Container, Kubernetes, repository, and configuration scanning.", "url": "https://trivy.dev/docs/latest/", "binaries": ("trivy",)},
        ),
    },
    {
        "name": "Network and host monitoring",
        "tools": (
            {"name": "Suricata", "summary": "Network intrusion detection and traffic inspection.", "url": "https://suricata.io/documentation/", "binaries": ("suricata",)},
            {"name": "Zeek", "summary": "Network traffic metadata and protocol analysis.", "url": "https://docs.zeek.org/", "binaries": ("zeek",)},
            {"name": "Wazuh", "summary": "Endpoint monitoring, log analysis, and host security telemetry.", "url": "https://documentation.wazuh.com/current/", "binaries": ("wazuh-agent", "wazuh-control", "wazuh-manager")},
            {"name": "osquery", "summary": "SQL-style host inventory and endpoint queries.", "url": "https://osquery.io/", "binaries": ("osqueryi",)},
        ),
    },
    {
        "name": "Enrichment and case management",
        "tools": (
            {"name": "MISP", "summary": "Threat-indicator sharing and enrichment platform.", "url": "https://www.misp-project.org/", "api": True},
            {"name": "OpenCTI", "summary": "Threat-intelligence knowledge graph and connector platform.", "url": "https://docs.opencti.io/latest/", "api": True},
            {"name": "VirusTotal", "summary": "Reputation and context lookups for hashes, domains, and IPs.", "url": "https://docs.virustotal.com/reference/overview", "api": True},
            {"name": "AbuseIPDB", "summary": "Abuse and reputation context for public IP addresses.", "url": "https://docs.abuseipdb.com/", "api": True},
            {"name": "DefectDojo", "summary": "Finding import, deduplication, triage, and remediation tracking.", "url": "https://docs.defectdojo.com/", "api": True},
        ),
    },
)


def catalog_tool_status(tool: dict[str, Any], scanner_availability: dict[str, tuple[bool, str]],
                        app_settings: dict[str, str]) -> tuple[str, str]:
    """Describe whether a listed product is wired into this app or needs setup."""
    integration = tool.get("integration")
    if integration == "openvas":
        return "Report import", "Import completed XML from the Scanner reports page."
    if integration:
        ready, detail = scanner_availability[integration]
        if integration == "burp":
            ready = bool(app_settings.get("burp_api_url") and app_settings.get("burp_api_key"))
            detail = app_settings.get("burp_api_url", "") if ready else "Save the Burp REST API URL and key in Settings."
        return ("Integrated · ready", detail) if ready else ("Integrated · setup needed", detail)
    if tool.get("api"):
        return "API connector not configured", "Needs an endpoint, credentials, and result-normalization adapter."
    binaries = tool.get("binaries", ())
    found = next(((name, shutil.which(name)) for name in binaries if shutil.which(name)), None)
    if found:
        return "Installed · adapter needed", found[1] or ""
    return "Optional · not installed", f"Expected command: {' / '.join(binaries)}"
