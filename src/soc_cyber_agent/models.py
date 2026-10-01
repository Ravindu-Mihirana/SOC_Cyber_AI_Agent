"""Shared normalized data structures for scan jobs and findings."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Literal

Severity = Literal["info", "low", "medium", "high", "critical", "unknown"]
JobStatus = Literal["queued", "running", "done", "failed"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class Finding:
    id: str
    source_tool: str
    target: str
    host: str
    port: int | None
    protocol: str | None
    title: str
    description: str
    severity: Severity
    cve_ids: list[str]
    evidence: str
    raw_ref: str
    timestamp: datetime
    status: str = "open"
    service_name: str | None = None
    service_product: str | None = None
    service_version: str | None = None
    service_detection_method: str | None = None
    service_confidence: int | None = None

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        return result


@dataclass(slots=True)
class ScanJob:
    id: str
    target: str
    status: JobStatus
    started_at: datetime
    finished_at: datetime | None = None
    error: str | None = None
    raw_path: str | None = None

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["started_at"] = self.started_at.isoformat()
        result["finished_at"] = self.finished_at.isoformat() if self.finished_at else None
        return result
