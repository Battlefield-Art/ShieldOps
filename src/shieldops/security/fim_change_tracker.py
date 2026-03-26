"""FIM Change Tracker — track file changes and compliance impact."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MonitoredPath(StrEnum):
    SYSTEM_CONFIG = "system_config"
    APPLICATION_BIN = "application_bin"
    SECURITY_POLICY = "security_policy"
    LOG_DIRECTORY = "log_directory"
    USER_DATA = "user_data"


class ChangeFrequency(StrEnum):
    FIRST_TIME = "first_time"
    RARE = "rare"
    OCCASIONAL = "occasional"
    FREQUENT = "frequent"
    CONSTANT = "constant"


class ComplianceImpact(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


# --- Models ---


class FIMChangeRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_path: str = ""
    monitored_path: MonitoredPath = MonitoredPath.SYSTEM_CONFIG
    change_frequency: ChangeFrequency = ChangeFrequency.FIRST_TIME
    compliance_impact: ComplianceImpact = ComplianceImpact.MEDIUM
    hash_before: str = ""
    hash_after: str = ""
    change_type: str = "modified"
    authorized: bool = False
    actor: str = ""
    created_at: float = Field(default_factory=time.time)


class FIMChangeAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    change_id: str = ""
    risk_score: float = 0.0
    is_anomalous: bool = False
    similar_changes: int = 0
    analyzed_at: float = Field(default_factory=time.time)


class FIMChangeReport(BaseModel):
    total_changes: int = 0
    unauthorized_count: int = 0
    critical_impact_count: int = 0
    by_path_type: dict[str, int] = Field(default_factory=dict)
    by_frequency: dict[str, int] = Field(default_factory=dict)
    by_compliance: dict[str, int] = Field(default_factory=dict)
    compliance_evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class FIMChangeTracker:
    """Track file integrity changes and compliance impact."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[FIMChangeRecord] = []
        logger.info(
            "fim_change_tracker.initialized",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> FIMChangeRecord:
        record = FIMChangeRecord(**kwargs)
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "fim_change_tracker.record_added",
            record_id=record.id,
            file_path=record.file_path,
        )
        return record

    def process(self, key: str) -> dict[str, Any]:
        matches = [r for r in self._records if r.id == key]
        if not matches:
            return {"found": False, "key": key}
        rec = matches[0]
        return {
            "found": True,
            "id": rec.id,
            "file_path": rec.file_path,
            "authorized": rec.authorized,
        }

    # -- domain methods --

    def track_change(
        self,
        file_path: str,
        monitored_path: MonitoredPath = MonitoredPath.SYSTEM_CONFIG,
        hash_before: str = "",
        hash_after: str = "",
        change_type: str = "modified",
        authorized: bool = False,
        actor: str = "",
    ) -> FIMChangeRecord:
        """Track a file change event."""
        prev = [r for r in self._records if r.file_path == file_path]
        if not prev:
            freq = ChangeFrequency.FIRST_TIME
        elif len(prev) < 3:
            freq = ChangeFrequency.RARE
        elif len(prev) < 10:
            freq = ChangeFrequency.OCCASIONAL
        else:
            freq = ChangeFrequency.FREQUENT
        impact = ComplianceImpact.MEDIUM
        if monitored_path == MonitoredPath.SECURITY_POLICY:
            impact = ComplianceImpact.CRITICAL
        elif monitored_path == MonitoredPath.SYSTEM_CONFIG:
            impact = ComplianceImpact.HIGH
        record = self.add_record(
            file_path=file_path,
            monitored_path=monitored_path,
            change_frequency=freq,
            compliance_impact=impact,
            hash_before=hash_before,
            hash_after=hash_after,
            change_type=change_type,
            authorized=authorized,
            actor=actor,
        )
        return record

    def detect_unauthorized_modification(
        self,
    ) -> list[dict[str, Any]]:
        """Detect unauthorized file modifications."""
        unauthorized = [r for r in self._records if not r.authorized]
        results: list[dict[str, Any]] = []
        for r in unauthorized:
            results.append(
                {
                    "change_id": r.id,
                    "file_path": r.file_path,
                    "change_type": r.change_type,
                    "compliance_impact": r.compliance_impact.value,
                    "actor": r.actor,
                    "timestamp": r.created_at,
                }
            )
        results.sort(key=lambda x: x["timestamp"], reverse=True)
        return results[:50]

    def generate_compliance_evidence(self) -> list[dict[str, Any]]:
        """Generate compliance evidence for audit."""
        evidence: list[dict[str, Any]] = []
        for r in self._records:
            if r.compliance_impact in (
                ComplianceImpact.CRITICAL,
                ComplianceImpact.HIGH,
            ):
                evidence.append(
                    {
                        "change_id": r.id,
                        "file_path": r.file_path,
                        "impact": r.compliance_impact.value,
                        "authorized": r.authorized,
                        "actor": r.actor,
                        "hash_before": r.hash_before,
                        "hash_after": r.hash_after,
                        "timestamp": r.created_at,
                    }
                )
        return evidence

    # -- report / stats --

    def generate_report(self) -> FIMChangeReport:
        by_path: dict[str, int] = {}
        by_freq: dict[str, int] = {}
        by_comp: dict[str, int] = {}
        for r in self._records:
            by_path[r.monitored_path.value] = by_path.get(r.monitored_path.value, 0) + 1
            by_freq[r.change_frequency.value] = by_freq.get(r.change_frequency.value, 0) + 1
            by_comp[r.compliance_impact.value] = by_comp.get(r.compliance_impact.value, 0) + 1
        unauth = sum(1 for r in self._records if not r.authorized)
        crit = by_comp.get("critical", 0)
        evidence = self.generate_compliance_evidence()
        ev_summaries = [f"{e['file_path']} ({e['impact']})" for e in evidence[:10]]
        recs: list[str] = []
        if unauth > 0:
            recs.append(f"{unauth} unauthorized modification(s) detected")
        if crit > 0:
            recs.append(f"{crit} change(s) with critical compliance impact")
        if not recs:
            recs.append("File integrity monitoring nominal")
        return FIMChangeReport(
            total_changes=len(self._records),
            unauthorized_count=unauth,
            critical_impact_count=crit,
            by_path_type=by_path,
            by_frequency=by_freq,
            by_compliance=by_comp,
            compliance_evidence=ev_summaries,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "unauthorized": sum(1 for r in self._records if not r.authorized),
            "unique_files": len({r.file_path for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("fim_change_tracker.cleared")
        return {"status": "cleared"}
