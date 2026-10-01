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
            analyses TEXT NOT NULL DEFAULT '{}'
        )
    """)
    connection.commit()
    return connection


def save_assessment(assessment: dict[str, Any]) -> None:
    with closing(_connect()) as connection:
        connection.execute("""
            INSERT INTO assessments(id, created_at, target, scanners, status, findings, scanner_results, analyses)
            VALUES (:id, :created_at, :target, :scanners, :status, :findings, :scanner_results, :analyses)
            ON CONFLICT(id) DO UPDATE SET
                status=excluded.status,
                findings=excluded.findings,
                scanner_results=excluded.scanner_results,
                analyses=excluded.analyses
        """, {
            "id": assessment["id"],
            "created_at": assessment["created_at"],
            "target": assessment["target"],
            "scanners": json.dumps(assessment["scanners"]),
            "status": assessment["status"],
            "findings": json.dumps(assessment.get("findings", [])),
            "scanner_results": json.dumps(assessment.get("scanner_results", {})),
            "analyses": json.dumps(assessment.get("analyses", {})),
        })
        connection.commit()


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


def new_assessment(target: str, scanners: list[str]) -> dict[str, Any]:
    from uuid import uuid4

    return {
        "id": str(uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scanners": scanners,
        "status": "running",
        "findings": [],
        "scanner_results": {},
        "analyses": {},
    }
