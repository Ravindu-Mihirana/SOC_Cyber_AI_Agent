"""Small local SQLite store for assessment history and AI analysis."""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


def data_dir() -> Path:
    configured = os.environ.get("SOC_AGENT_DATA_DIR")
    path = Path(configured) if configured else Path.cwd() / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return data_dir() / "assessments.sqlite3"


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(db_path())
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            target TEXT NOT NULL,
            scanners TEXT NOT NULL,
            status TEXT NOT NULL,
            findings TEXT NOT NULL DEFAULT '[]',
            scanner_results TEXT NOT NULL DEFAULT '{}',
            analyses TEXT NOT NULL DEFAULT '{}',
            group_id TEXT NOT NULL DEFAULT '',
            scan_number INTEGER NOT NULL DEFAULT 1,
            scan_config TEXT NOT NULL DEFAULT '{}'
        )
    """)
    existing = {row["name"] for row in connection.execute("PRAGMA table_info(assessments)")}
    for name, declaration in (
        ("group_id", "TEXT NOT NULL DEFAULT ''"),
        ("scan_number", "INTEGER NOT NULL DEFAULT 1"),
        ("scan_config", "TEXT NOT NULL DEFAULT '{}'"),
    ):
        if name not in existing:
            connection.execute(f"ALTER TABLE assessments ADD COLUMN {name} {declaration}")
    connection.commit()
    return connection


def save_assessment(assessment: dict[str, Any]) -> None:
    with closing(_connect()) as connection:
        connection.execute("""
            INSERT INTO assessments(id, created_at, target, scanners, status, findings, scanner_results, analyses, group_id, scan_number, scan_config)
            VALUES (:id, :created_at, :target, :scanners, :status, :findings, :scanner_results, :analyses, :group_id, :scan_number, :scan_config)
            ON CONFLICT(id) DO UPDATE SET
                status=excluded.status,
                findings=excluded.findings,
                scanner_results=excluded.scanner_results,
                analyses=excluded.analyses,
                group_id=excluded.group_id,
                scan_number=excluded.scan_number,
                scan_config=excluded.scan_config
        """, {
            "id": assessment["id"],
            "created_at": assessment["created_at"],
            "target": assessment["target"],
            "scanners": json.dumps(assessment["scanners"]),
            "status": assessment["status"],
            "findings": json.dumps(assessment.get("findings", [])),
            "scanner_results": json.dumps(assessment.get("scanner_results", {})),
            "analyses": json.dumps(assessment.get("analyses", {})),
            "group_id": assessment.get("group_id", assessment["id"]),
            "scan_number": assessment.get("scan_number", 1),
            "scan_config": json.dumps(assessment.get("scan_config", {})),
        })
        connection.commit()


def save_analysis(assessment_id: str, analysis: str) -> bool:
    """Update only analysis data so a concurrent scanner save cannot be lost."""
    with closing(_connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT analyses FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
        if not row:
            connection.rollback()
            return False
        analyses = json.loads(row["analyses"])
        analyses["unified"] = analysis
        connection.execute("UPDATE assessments SET analyses = ? WHERE id = ?", (json.dumps(analyses), assessment_id))
        connection.commit()
    return True


def _decode(row: sqlite3.Row) -> dict[str, Any]:
    scanner_results = json.loads(row["scanner_results"])
    # Older Windows assessments saved absolute paths. Preserve their report
    # references after moving the data directory to Linux.
    for result in scanner_results.values():
        raw_path = result.get("raw_path")
        if raw_path:
            result["raw_path"] = _portable_raw_reference(str(raw_path))
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "target": row["target"],
        "scanners": json.loads(row["scanners"]),
        "status": row["status"],
        "findings": json.loads(row["findings"]),
        "scanner_results": scanner_results,
        "analyses": json.loads(row["analyses"]),
        "group_id": row["group_id"] or row["id"],
        "scan_number": row["scan_number"],
        "scan_config": json.loads(row["scan_config"]),
    }


def _portable_raw_reference(value: str) -> str:
    normalized = value.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part and part != "."]
    data_indexes = [index for index, part in enumerate(parts) if part.casefold() == "data"]
    if data_indexes:
        parts = parts[data_indexes[-1] + 1:]
    elif normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        parts = ["raw", parts[-1]] if parts else []
    if parts and parts[0].casefold() == "raw":
        return PurePosixPath(*parts).as_posix()
    if parts and parts[0].casefold() == "inbox":
        return PurePosixPath(*parts).as_posix()
    return PurePosixPath("raw", parts[-1]).as_posix() if parts else value


def get_assessment(assessment_id: str) -> dict[str, Any] | None:
    with closing(_connect()) as connection:
        row = connection.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
    return _decode(row) if row else None


def list_assessments(limit: int = 100) -> list[dict[str, Any]]:
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT * FROM assessments ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_decode(row) for row in rows]


def recover_interrupted_assessments() -> int:
    """Mark scans left active by a prior process as interrupted after startup."""
    with closing(_connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute("SELECT id, scanner_results FROM assessments WHERE status = 'running'").fetchall()
        for row in rows:
            results = json.loads(row["scanner_results"])
            for name, result in results.items():
                if result.get("status") in {"queued", "running"}:
                    result["status"] = "failed"
                    result["error"] = "Scan was interrupted when the application stopped. Start a new scan to retry."
            completed = any(result.get("status") == "complete" for result in results.values())
            connection.execute(
                "UPDATE assessments SET status = ?, scanner_results = ? WHERE id = ?",
                ("complete" if completed and not any(item.get("status") == "failed" for item in results.values()) else "partial" if completed else "failed", json.dumps(results), row["id"]),
            )
        connection.commit()
    return len(rows)


def list_assessment_scans(group_id: str) -> list[dict[str, Any]]:
    """Return every saved run in one target's scan lineage, oldest first."""
    with closing(_connect()) as connection:
        rows = connection.execute(
            "SELECT * FROM assessments WHERE group_id = ? OR (group_id = '' AND id = ?) ORDER BY scan_number, created_at",
            (group_id, group_id),
        ).fetchall()
    return [_decode(row) for row in rows]


def next_scan_number(group_id: str) -> int:
    with closing(_connect()) as connection:
        row = connection.execute(
            "SELECT MAX(scan_number) AS latest FROM assessments WHERE group_id = ? OR (group_id = '' AND id = ?)",
            (group_id, group_id),
        ).fetchone()
    return int(row["latest"] or 0) + 1


def delete_assessment(assessment_id: str) -> dict[str, Any] | None:
    """Delete one assessment record and return its data for evidence cleanup."""
    with closing(_connect()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
        if not row:
            connection.rollback()
            return None
        assessment = _decode(row)
        connection.execute("DELETE FROM assessments WHERE id = ?", (assessment_id,))
        connection.commit()
    return assessment


def new_assessment(target: str, scanners: list[str], *, group_id: str | None = None,
                   scan_number: int = 1, scan_config: dict[str, Any] | None = None) -> dict[str, Any]:
    from uuid import uuid4

    assessment_id = str(uuid4())
    return {
        "id": assessment_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scanners": scanners,
        "status": "running",
        "findings": [],
        "scanner_results": {},
        "analyses": {},
        "group_id": group_id or assessment_id,
        "scan_number": scan_number,
        "scan_config": scan_config or {},
    }
