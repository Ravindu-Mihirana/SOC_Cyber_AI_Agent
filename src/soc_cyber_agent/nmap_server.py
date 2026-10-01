"""MCP server exposing a bounded Nmap scan and its results."""

import asyncio
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

from .models import ScanJob
from .nmap_parser import parse_nmap_xml
from .web_parsers import parse_gobuster_text, parse_nikto_json

mcp = FastMCP("soc-cyber-nmap")
_jobs: dict[str, ScanJob] = {}
_tasks: dict[str, asyncio.Task[None]] = {}
_job_tools: dict[str, str] = {}


def _authorized_web_url(target_url: str) -> str | None:
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return None
    try:
        parsed.port
    except ValueError:
        return None
    return target_url


def _nikto_command() -> list[str] | None:
    executable = shutil.which("nikto")
    if executable:
        return [executable]
    script = os.environ.get("NIKTO_SCRIPT")
    perl = shutil.which("perl")
    if script and Path(script).is_file() and perl:
        return [perl, script]
    return None


async def _run_command(job: ScanJob, args: list[str]) -> None:
    job.status = "running"
    try:
        process = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await process.communicate()
        if process.returncode != 0:
            job.status = "failed"
            job.error = stderr.decode(errors="replace")[-2000:]
        else:
            job.status = "done"
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
    finally:
        job.finished_at = datetime.now(timezone.utc)


async def _run_nmap(job: ScanJob, scan_type: str, ports: str | None) -> None:
    job.status = "running"
    output_path = Path(tempfile.gettempdir()) / f"soc-cyber-nmap-{job.id}.xml"
    job.raw_path = str(output_path)
    args = ["nmap", "-oX", str(output_path)]
    if scan_type == "quick":
        args.extend(["-T3", "-F"])
    elif scan_type == "version":
        args.extend(["-T3", "-sV", "--top-ports", "100"])
    else:
        job.status = "failed"
        job.error = "Unsupported scan profile. Choose quick or version."
        job.finished_at = datetime.now(timezone.utc)
        return
    if ports:
        if not all(char in "0123456789,-" for char in ports):
            job.status = "failed"
            job.error = "Ports must contain only digits, commas, and hyphens."
            job.finished_at = datetime.now(timezone.utc)
            return
        args.extend(["-p", ports])
    args.append(job.target)
    try:
        process = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await process.communicate()
        if process.returncode != 0:
            job.status = "failed"
            job.error = stderr.decode(errors="replace")[-2000:]
        else:
            job.status = "done"
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
    finally:
        job.finished_at = datetime.now(timezone.utc)


@mcp.tool()
async def run_nmap_scan(target: str, scan_type: str = "quick", ports: str | None = None) -> dict[str, str]:
    """Start a quick or version-detection scan of an authorized target."""
    if not shutil.which("nmap"):
        return {"error": "Nmap executable was not found on PATH."}
    if not target or target.startswith("-") or any(char.isspace() for char in target):
        return {"error": "Provide a single hostname or IP address as the target."}
    if scan_type not in {"quick", "version"}:
        return {"error": "scan_type must be quick or version."}
    job_id = str(uuid.uuid4())
    job = ScanJob(id=job_id, target=target, status="queued", started_at=datetime.now(timezone.utc))
    _jobs[job_id] = job
    _tasks[job_id] = asyncio.create_task(_run_nmap(job, scan_type, ports))
    return {"job_id": job_id, "status": job.status}


@mcp.tool()
async def get_scan_status(job_id: str) -> dict[str, object]:
    """Get the lifecycle status of a scan job."""
    job = _jobs.get(job_id)
    return job.to_dict() if job else {"error": "Unknown job_id."}


@mcp.tool()
async def get_scan_results(job_id: str) -> dict[str, object]:
    """Return normalized open-port findings for a completed scan."""
    job = _jobs.get(job_id)
    if not job:
        return {"error": "Unknown job_id."}
    if job.status != "done" or not job.raw_path:
        return {"error": f"Scan is not complete (status: {job.status})."}
    findings = parse_nmap_xml(job.raw_path, target=job.target, job_id=job.id)
    return {"job_id": job.id, "findings": [finding.to_dict() for finding in findings]}


@mcp.tool()
async def run_nikto_scan(target_url: str) -> dict[str, str]:
    """Run Nikto against an authorized HTTP(S) URL and save JSON results."""
    if not _authorized_web_url(target_url):
        return {"error": "target_url must be a valid http:// or https:// URL without credentials."}
    command = _nikto_command()
    if not command:
        return {"error": "Nikto executable was not found on PATH."}
    job_id = str(uuid.uuid4())
    output_path = Path(tempfile.gettempdir()) / f"soc-cyber-nikto-{job_id}.json"
    job = ScanJob(id=job_id, target=target_url, status="queued", started_at=datetime.now(timezone.utc), raw_path=str(output_path))
    _jobs[job_id] = job
    _job_tools[job_id] = "nikto"
    args = command + ["-h", target_url, "-output", str(output_path), "-Format", "json", "-maxtime", "5m", "-timeout", "10", "-nointeractive", "-nocheck"]
    _tasks[job_id] = asyncio.create_task(_run_command(job, args))
    return {"job_id": job_id, "status": job.status}


@mcp.tool()
async def run_gobuster_scan(target_url: str, wordlist: str) -> dict[str, str]:
    """Run a low-thread Gobuster directory scan using a local wordlist."""
    if not _authorized_web_url(target_url):
        return {"error": "target_url must be a valid http:// or https:// URL without credentials."}
    wordlist_path = Path(wordlist).expanduser().resolve()
    if not wordlist_path.is_file():
        return {"error": "wordlist must point to an existing local file."}
    executable = shutil.which("gobuster")
    if not executable:
        return {"error": "Gobuster executable was not found on PATH."}
    job_id = str(uuid.uuid4())
    output_path = Path(tempfile.gettempdir()) / f"soc-cyber-gobuster-{job_id}.txt"
    job = ScanJob(id=job_id, target=target_url, status="queued", started_at=datetime.now(timezone.utc), raw_path=str(output_path))
    _jobs[job_id] = job
    _job_tools[job_id] = "gobuster"
    args = [executable, "dir", "-u", target_url, "-w", str(wordlist_path), "-t", "10", "-q", "-o", str(output_path)]
    _tasks[job_id] = asyncio.create_task(_run_command(job, args))
    return {"job_id": job_id, "status": job.status}


@mcp.tool()
async def get_web_scan_results(job_id: str) -> dict[str, object]:
    """Return normalized results for a completed Nikto or Gobuster scan."""
    job = _jobs.get(job_id)
    if not job:
        return {"error": "Unknown job_id."}
    if job.status != "done" or not job.raw_path:
        return {"error": f"Scan is not complete (status: {job.status})."}
    if not Path(job.raw_path).is_file():
        return {"error": "Scanner completed without producing its output file."}
    scanner = _job_tools.get(job_id)
    if scanner == "nikto":
        findings = parse_nikto_json(job.raw_path, target=job.target, job_id=job.id)
    elif scanner == "gobuster":
        findings = parse_gobuster_text(job.raw_path, target=job.target, job_id=job.id)
    else:
        return {"error": "Job is not a web scanner job."}
    return {"job_id": job.id, "findings": [finding.to_dict() for finding in findings]}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
