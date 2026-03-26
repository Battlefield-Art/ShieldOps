"""Data Anomaly Detector — detect unexpected data changes, deletions, encryption events."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AnomalySource(StrEnum):
    DATABASE = "database"
    OBJECT_STORAGE = "object_storage"
    FILE_SYSTEM = "file_system"
    BACKUP_SYSTEM = "backup_system"
    API_LAYER = "api_layer"


class ChangeType(StrEnum):
    UNEXPECTED_MODIFICATION = "unexpected_modification"
    BULK_DELETION = "bulk_deletion"
    ENCRYPTION_EVENT = "encryption_event"
    PERMISSION_CHANGE = "permission_change"
    SCHEMA_ALTERATION = "schema_alteration"


class SeverityLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --- Models ---


class AnomalyRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    anomaly_name: str = ""
    anomaly_source: AnomalySource = AnomalySource.DATABASE
    change_type: ChangeType = ChangeType.UNEXPECTED_MODIFICATION
    severity_level: SeverityLevel = SeverityLevel.MEDIUM
    anomaly_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AnomalyAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    anomaly_name: str = ""
    anomaly_source: AnomalySource = AnomalySource.DATABASE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AnomalyReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    critical_count: int = 0
    avg_anomaly_score: float = 0.0
    by_source: dict[str, int] = Field(default_factory=dict)
    by_change_type: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    top_anomalies: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class DataAnomalyDetector:
    """Detect unexpected data changes, deletion attempts, and encryption events."""

    def __init__(
        self,
        max_records: int = 200000,
        anomaly_threshold: float = 65.0,
    ) -> None:
        self._max_records = max_records
        self._anomaly_threshold = anomaly_threshold
        self._records: list[AnomalyRecord] = []
        self._analyses: list[AnomalyAnalysis] = []
        logger.info(
            "data_anomaly_detector.initialized",
            max_records=max_records,
            anomaly_threshold=anomaly_threshold,
        )

    # -- record / get / list ----------------------------

    def add_record(
        self,
        anomaly_name: str,
        anomaly_source: AnomalySource = (AnomalySource.DATABASE),
        change_type: ChangeType = (ChangeType.UNEXPECTED_MODIFICATION),
        severity_level: SeverityLevel = (SeverityLevel.MEDIUM),
        anomaly_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> AnomalyRecord:
        record = AnomalyRecord(
            anomaly_name=anomaly_name,
            anomaly_source=anomaly_source,
            change_type=change_type,
            severity_level=severity_level,
            anomaly_score=anomaly_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "data_anomaly_detector.record_added",
            record_id=record.id,
            anomaly_name=anomaly_name,
            anomaly_source=anomaly_source.value,
        )
        return record

    def get_record(self, record_id: str) -> AnomalyRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        anomaly_source: AnomalySource | None = None,
        change_type: ChangeType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AnomalyRecord]:
        results = list(self._records)
        if anomaly_source is not None:
            results = [r for r in results if r.anomaly_source == anomaly_source]
        if change_type is not None:
            results = [r for r in results if r.change_type == change_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        anomaly_name: str,
        anomaly_source: AnomalySource = (AnomalySource.DATABASE),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AnomalyAnalysis:
        analysis = AnomalyAnalysis(
            anomaly_name=anomaly_name,
            anomaly_source=anomaly_source,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "data_anomaly_detector.analysis_added",
            anomaly_name=anomaly_name,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ------------------------------

    def detect_unexpected_changes(
        self,
    ) -> dict[str, Any]:
        """Group by anomaly_source; return count and avg anomaly_score."""
        source_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.anomaly_source.value
            source_data.setdefault(key, []).append(r.anomaly_score)
        result: dict[str, Any] = {}
        for source, scores in source_data.items():
            result[source] = {
                "count": len(scores),
                "avg_anomaly_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def track_deletion_attempts(
        self,
    ) -> list[dict[str, Any]]:
        """Return bulk deletion records above threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if (
                r.change_type == ChangeType.BULK_DELETION
                and r.anomaly_score >= self._anomaly_threshold
            ):
                results.append(
                    {
                        "record_id": r.id,
                        "anomaly_name": r.anomaly_name,
                        "anomaly_source": (r.anomaly_source.value),
                        "anomaly_score": (r.anomaly_score),
                        "service": r.service,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["anomaly_score"],
            reverse=True,
        )

    def alert_on_encryption_events(
        self,
    ) -> list[dict[str, Any]]:
        """Return encryption event records, sorted by score."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.change_type == ChangeType.ENCRYPTION_EVENT:
                results.append(
                    {
                        "record_id": r.id,
                        "anomaly_name": r.anomaly_name,
                        "anomaly_source": (r.anomaly_source.value),
                        "severity_level": (r.severity_level.value),
                        "anomaly_score": (r.anomaly_score),
                        "service": r.service,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["anomaly_score"],
            reverse=True,
        )

    # -- report / stats ---------------------------------

    def generate_report(self) -> AnomalyReport:
        by_source: dict[str, int] = {}
        by_change_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for r in self._records:
            by_source[r.anomaly_source.value] = by_source.get(r.anomaly_source.value, 0) + 1
            by_change_type[r.change_type.value] = by_change_type.get(r.change_type.value, 0) + 1
            by_severity[r.severity_level.value] = by_severity.get(r.severity_level.value, 0) + 1
        critical_count = sum(1 for r in self._records if r.anomaly_score >= self._anomaly_threshold)
        scores = [r.anomaly_score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        top = [
            r.anomaly_name
            for r in sorted(
                self._records,
                key=lambda x: x.anomaly_score,
                reverse=True,
            )[:5]
        ]
        recs: list[str] = []
        if critical_count > 0:
            recs.append(
                f"{critical_count} anomaly/anomalies above threshold ({self._anomaly_threshold})"
            )
        if not recs:
            recs.append("No significant data anomalies")
        return AnomalyReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            critical_count=critical_count,
            avg_anomaly_score=avg,
            by_source=by_source,
            by_change_type=by_change_type,
            by_severity=by_severity,
            top_anomalies=top,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("data_anomaly_detector.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        source_dist: dict[str, int] = {}
        for r in self._records:
            key = r.anomaly_source.value
            source_dist[key] = source_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "anomaly_threshold": (self._anomaly_threshold),
            "source_distribution": source_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
