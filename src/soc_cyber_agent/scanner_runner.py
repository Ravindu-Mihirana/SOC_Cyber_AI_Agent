"""Direct scanner adapters shared by the UI; all invocations avoid a shell."""

import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlparse

from .models import Finding
from .nmap_parser import parse_nmap_xml
from .storage import data_dir
from .web_parsers import parse_gobuster_text, parse_nikto_json

SCANNERS = ("nmap", "nikto", "gobuster")


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
    return {
        "nmap": (bool(nmap), nmap or "Nmap executable not found on PATH"),
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


def run_scan(
    scanner: str,
    target: str,
    *,
    scan_type: str = "quick",
    ports: str = "",
    wordlist: str = "",
) -> tuple[list[dict[str, object]], str]:
    """Execute one scan and return normalized findings plus the raw-output path."""
    if scanner not in SCANNERS:
        raise ScannerError(f"Unknown scanner: {scanner}")
    job_id = str(uuid.uuid4())
    raw_dir = data_dir() / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

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
