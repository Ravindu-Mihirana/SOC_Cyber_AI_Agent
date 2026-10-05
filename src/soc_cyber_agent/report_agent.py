"""Background agent that ingests exported scanner reports from a drop folder."""

import shutil
import hashlib
import threading
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from .report_importers import ReportImportError, parse_burp_xml, parse_openvas_xml
from .storage import data_dir, new_assessment, save_assessment

POLL_SECONDS = 3
_lock = threading.RLock()
_stop_event: threading.Event | None = None
_thread: threading.Thread | None = None
_state: dict[str, Any] = {
    "running": False,
    "processed": 0,
    "last_file": "",
    "last_assessment_id": "",
    "last_error": "",
    "started_at": "",
}


def inbox_dir() -> Path:
    path = data_dir() / "inbox"
    path.mkdir(parents=True, exist_ok=True)
    return path


def agent_status() -> dict[str, Any]:
    with _lock:
        status = dict(_state)
    status["inbox"] = str(inbox_dir())
    return status


def start_report_agent() -> dict[str, Any]:
    global _stop_event, _thread
    with _lock:
        if _thread is not None and _thread.is_alive():
            _state["running"] = True
            return dict(_state)
        _stop_event = threading.Event()
        _state.update({"running": True, "last_error": "", "started_at": time.strftime("%Y-%m-%d %H:%M:%S")})
        _thread = threading.Thread(target=_worker, args=(_stop_event,), name="report-ingest-agent", daemon=True)
        _thread.start()
        return dict(_state)


def stop_report_agent() -> dict[str, Any]:
    with _lock:
        if _stop_event is not None:
            _stop_event.set()
        _state["running"] = False
        return dict(_state)


def _worker(stop_event: threading.Event) -> None:
    stable: dict[Path, tuple[int, int, int]] = {}
    while not stop_event.is_set():
        try:
            for path in inbox_dir().glob("*.xml"):
                if stop_event.is_set():
                    break
                try:
                    stat = path.stat()
                    size, modified = stat.st_size, stat.st_mtime_ns
                    previous = stable.get(path)
                    count = previous[2] + 1 if previous and previous[:2] == (size, modified) else 0
                    stable[path] = (size, modified, count)
                    if count < 1:
                        continue
                    _ingest(path)
                    stable.pop(path, None)
                except FileNotFoundError:
                    stable.pop(path, None)
                except Exception as exc:  # keep the agent alive; show actionable error in UI
                    with _lock:
                        _state["last_error"] = f"{path.name}: {exc}"
        except Exception as exc:
            with _lock:
                _state["last_error"] = str(exc)
        stop_event.wait(POLL_SECONDS)
    with _lock:
        if _stop_event is stop_event:
            _state["running"] = False


def _ingest(path: Path) -> None:
    name = path.name.lower()
    if name.startswith("burp-"):
        scanner, parser = "burp", parse_burp_xml
    elif name.startswith(("openvas-", "gvm-")):
        scanner, parser = "openvas", parse_openvas_xml
    else:
        return

    content = path.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    processed_dir = inbox_dir() / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)
    # Content-based archive naming makes retries after a partial move/save
    # failure idempotent and preserves the report's original bytes.
    archived = data_dir() / "raw" / f"agent-{scanner}-{digest}.xml"
    destination = processed_dir / f"{path.stem}-{digest[:10]}{path.suffix}"
    if destination.exists():
        path.unlink(missing_ok=True)
        return
    if archived.exists():
        shutil.move(str(path), str(destination))
        return
    report_id = str(uuid4())
    findings = parser(content, raw_ref=report_id)
    raw_dir = data_dir() / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, archived)

    targets = sorted({finding.target for finding in findings})
    assessment = new_assessment(f"Auto-imported {scanner.title()}: {', '.join(targets) or 'unknown target'}", [scanner])
    assessment["status"] = "complete"
    assessment["findings"] = [finding.to_dict() for finding in findings]
    assessment["scanner_results"][scanner] = {
        "status": "complete", "target": ", ".join(targets), "count": len(findings),
        "raw_path": archived.relative_to(data_dir()).as_posix(), "mode": "automatically imported report",
    }
    save_assessment(assessment)
    shutil.move(str(path), str(destination))
    with _lock:
        _state["processed"] += 1
        _state["last_file"] = path.name
        _state["last_assessment_id"] = assessment["id"]
        _state["last_error"] = ""
