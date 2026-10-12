"""Persistent, single-process scan queue for the Streamlit dashboard."""

import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from .app_settings import load_app_settings
from .scanner_runner import ScanControlRequested, run_scan
from .storage import (
    claim_scan_worker,
    data_dir,
    clear_assessment_control,
    get_assessment_control,
    get_assessment,
    list_pending_assessments,
    release_scan_worker,
    save_assessment,
    scan_worker_state,
    update_scan_worker_heartbeat,
)

HEARTBEAT_SECONDS = 4
POLL_SECONDS = 2
_logger = logging.getLogger("soc_cyber_agent.scan_worker")


def _pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def ensure_scan_worker_started() -> bool:
    """Start a detached queue worker if one is not already serving this DB."""
    state = scan_worker_state()
    if state and _pid_is_alive(int(state["pid"])):
        return True

    logs = data_dir() / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    log_file = (logs / "scan-worker.log").open("a", encoding="utf-8")
    project_root = Path(__file__).resolve().parents[2]
    flags = 0
    options: dict[str, Any] = {}
    if os.name == "nt":
        flags = getattr(subprocess, "DETACHED_PROCESS", 0x00000008) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        options["creationflags"] = flags
    else:
        options["start_new_session"] = True
    try:
        process = subprocess.Popen(
            [sys.executable, "-m", "soc_cyber_agent.scan_worker"],
            cwd=project_root,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            close_fds=True,
            **options,
        )
    except OSError:
        log_file.close()
        _logger.exception("Could not launch the persistent scan worker")
        return False
    log_file.close()
    # The child claims the SQLite worker lease before doing work. Avoid a
    # blocking wait here so dashboard reruns remain responsive.
    return process.pid > 0


def _heartbeat_loop(pid: int, stop: threading.Event) -> None:
    while not stop.wait(HEARTBEAT_SECONDS):
        if not update_scan_worker_heartbeat(pid):
            stop.set()


def _persist_scanner_state(assessment_id: str, scanner: str, update: dict[str, Any]) -> dict[str, Any] | None:
    assessment = get_assessment(assessment_id)
    if not assessment:
        return None
    current = assessment.setdefault("scanner_results", {}).setdefault(scanner, {})
    current.update(update)
    save_assessment(assessment)
    return assessment


def _available_memory_mb() -> int | None:
    """Read Linux's reclaimable RAM estimate; return None on other platforms."""
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _wait_for_memory(assessment_id: str, scanner: str, profile: str) -> None:
    if profile != "vm_safe":
        return
    threshold_mb = 1400 if scanner == "zap" else 700
    deadline = time.monotonic() + 120
    while True:
        control = get_assessment_control(assessment_id)
        if control in {"paused", "stopping"}:
            raise ScanControlRequested(control)
        available = _available_memory_mb()
        if available is None or available >= threshold_mb:
            return
        _persist_scanner_state(assessment_id, scanner, {
            "status": "queued",
            "detail": f"Waiting for VM memory: {available} MiB available; {threshold_mb} MiB required before starting.",
        })
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"VM-safe mode did not start {scanner.title()}: RAM stayed below {threshold_mb} MiB available for 2 minutes. "
                "Close memory-heavy applications or increase VM memory, then retry."
            )
        time.sleep(3)


def _run_assessment(assessment_id: str) -> None:
    assessment = get_assessment(assessment_id)
    if not assessment:
        return
    config = assessment.get("scan_config", {})
    settings = load_app_settings()

    for scanner in assessment.get("scanners", []):
        assessment = get_assessment(assessment_id)
        if not assessment:
            return
        config = assessment.get("scan_config", {})
        control = get_assessment_control(assessment_id)
        if control == "paused":
            assessment["status"] = "paused"
            save_assessment(assessment)
            return
        if control == "stopping":
            for pending_result in assessment.get("scanner_results", {}).values():
                if pending_result.get("status") in {"queued", "running"}:
                    pending_result.update(status="cancelled", detail="Not started because this assessment was stopped")
            assessment["status"] = "stopped"
            save_assessment(assessment)
            clear_assessment_control(assessment_id)
            return
        result = assessment.get("scanner_results", {}).get(scanner, {})
        if result.get("status") not in {"queued", "running"}:
            continue
        target = str(result.get("target") or "")
        resource_profile = str(config.get("resource_profile", "vm_safe"))

        def report_progress(message: str, scanner_name: str = scanner) -> None:
            import re
            update: dict[str, Any] = {"detail": message}
            match = re.search(r"(\d{1,3})%", message)
            if match:
                update["progress"] = min(100, int(match.group(1)))
            _persist_scanner_state(assessment_id, scanner_name, update)

        try:
            _wait_for_memory(assessment_id, scanner, resource_profile)
            _persist_scanner_state(assessment_id, scanner, {
                "status": "running", "target": target,
                "detail": f"Starting {scanner.title()} in the persistent scan queue",
                "error": "", "progress": 0,
            })
            findings, raw_path = run_scan(
                scanner,
                target,
                scan_type=str(config.get("scan_type", "quick")),
                ports=str(config.get("ports", "")),
                wordlist=str(config.get("wordlist", "")),
                burp_api_url=settings["burp_api_url"],
                burp_api_key=settings["burp_api_key"],
                burp_profile=str(config.get("burp_profile", "")),
                nmap_options=config.get("nmap_options", {}),
                resource_profile=resource_profile,
                on_progress=report_progress,
                control_check=lambda: get_assessment_control(assessment_id),
            )
            latest = get_assessment(assessment_id)
            if not latest:
                return
            latest["findings"].extend(findings)
            latest["scanner_results"][scanner] = {
                "status": "complete", "target": target, "count": len(findings),
                "raw_path": raw_path, "progress": 100,
            }
            save_assessment(latest)
        except ScanControlRequested:
            latest = get_assessment(assessment_id)
            if not latest:
                return
            requested = get_assessment_control(assessment_id)
            if requested == "stopping":
                for pending_result in latest.get("scanner_results", {}).values():
                    if pending_result.get("status") in {"queued", "running"}:
                        pending_result.update(status="cancelled", detail="Cancelled by stop request")
                latest["status"] = "stopped"
                save_assessment(latest)
                clear_assessment_control(assessment_id)
                return
            latest["scanner_results"][scanner].update(
                status="queued", progress=0,
                detail="Paused. Resume will restart this scanner from the beginning.",
                error="",
            )
            latest["status"] = "paused"
            save_assessment(latest)
            return
        except Exception as exc:
            _persist_scanner_state(assessment_id, scanner, {
                "status": "failed", "target": target, "error": str(exc), "progress": 100,
            })

    latest = get_assessment(assessment_id)
    if not latest:
        return
    control = get_assessment_control(assessment_id)
    if control == "paused":
        latest["status"] = "paused"
        save_assessment(latest)
        return
    if control == "stopping":
        for pending_result in latest.get("scanner_results", {}).values():
            if pending_result.get("status") in {"queued", "running"}:
                pending_result.update(status="cancelled", detail="Not started because this assessment was stopped")
        latest["status"] = "stopped"
        save_assessment(latest)
        clear_assessment_control(assessment_id)
        return
    statuses = [item.get("status") for item in latest.get("scanner_results", {}).values()]
    complete_count = sum(status == "complete" for status in statuses)
    failed_count = sum(status == "failed" for status in statuses)
    if any(status in {"queued", "running"} for status in statuses):
        # A shutdown or unexpected worker exception leaves the assessment
        # resumable; the next worker pass retries the current scanner.
        latest["status"] = "running"
    else:
        latest["status"] = "complete" if complete_count and not failed_count else "partial" if complete_count else "failed"
    save_assessment(latest)


def main() -> int:
    pid = os.getpid()
    if not claim_scan_worker(pid):
        return 0
    stop = threading.Event()
    heartbeat = threading.Thread(target=_heartbeat_loop, args=(pid, stop), name="scan-worker-heartbeat", daemon=True)
    heartbeat.start()
    _logger.info("Persistent scan queue started (pid=%s)", pid)
    try:
        while not stop.is_set():
            pending = list_pending_assessments()
            if not pending:
                stop.wait(POLL_SECONDS)
                continue
            for assessment in pending:
                if stop.is_set():
                    break
                try:
                    _run_assessment(assessment["id"])
                except Exception:
                    _logger.exception("Could not process assessment %s; it will be retried", assessment["id"])
                    stop.wait(POLL_SECONDS)
    except KeyboardInterrupt:
        _logger.info("Persistent scan queue stopping")
    except Exception:
        _logger.exception("Scan queue supervisor failed")
        return 1
    finally:
        stop.set()
        release_scan_worker(pid)
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    raise SystemExit(main())
