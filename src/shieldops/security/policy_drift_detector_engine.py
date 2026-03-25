"""Policy Drift Detector Engine — detect and track policy configuration drift."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DriftType(StrEnum):
    CONFIG_CHANGE = "config_change"
    PERMISSION_CREEP = "permission_creep"
    RULE_DELETION = "rule_deletion"
    SCOPE_EXPANSION = "scope_expansion"
    OVERRIDE = "override"


class DriftSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    COSMETIC = "cosmetic"


class ReconciliationStatus(StrEnum):
    PENDING = "pending"
    AUTO_FIXED = "auto_fixed"
    MANUAL_REQUIRED = "manual_required"
    ACCEPTED = "accepted"
    REVERTED = "reverted"


# --- Models ---


class PolicyDriftRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    drift_id: str = ""
    drift_type: DriftType = DriftType.CONFIG_CHANGE
    drift_severity: DriftSeverity = DriftSeverity.MEDIUM
    reconciliation_status: ReconciliationStatus = ReconciliationStatus.PENDING
    policy_name: str = ""
    expected_value: str = ""
    actual_value: str = ""
    auto_reconcilable: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class PolicyDriftAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    drift_id: str = ""
    drift_type: DriftType = DriftType.CONFIG_CHANGE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PolicyDriftReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_drifts_per_service: float = 0.0
    by_drift_type: dict[str, int] = Field(default_factory=dict)
    by_drift_severity: dict[str, int] = Field(default_factory=dict)
    by_reconciliation_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class PolicyDriftDetectorEngine:
    """Detect and track policy configuration drift."""

    def __init__(
        self,
        max_records: int = 200000,
        drift_threshold: float = 5.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = drift_threshold
        self._records: list[PolicyDriftRecord] = []
        self._analyses: list[PolicyDriftAnalysis] = []
        logger.info(
            "policy_drift_detector_engine.initialized",
            max_records=max_records,
            drift_threshold=drift_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        drift_id: str,
        drift_type: DriftType = DriftType.CONFIG_CHANGE,
        drift_severity: DriftSeverity = DriftSeverity.MEDIUM,
        reconciliation_status: ReconciliationStatus = ReconciliationStatus.PENDING,
        policy_name: str = "",
        expected_value: str = "",
        actual_value: str = "",
        auto_reconcilable: bool = False,
        service: str = "",
        team: str = "",
    ) -> PolicyDriftRecord:
        record = PolicyDriftRecord(
            drift_id=drift_id,
            drift_type=drift_type,
            drift_severity=drift_severity,
            reconciliation_status=reconciliation_status,
            policy_name=policy_name,
            expected_value=expected_value,
            actual_value=actual_value,
            auto_reconcilable=auto_reconcilable,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "policy_drift_detector_engine.record_added",
            record_id=record.id,
            drift_id=drift_id,
            drift_type=drift_type.value,
            drift_severity=drift_severity.value,
        )
        return record

    def get_record(self, record_id: str) -> PolicyDriftRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        drift_type: DriftType | None = None,
        drift_severity: DriftSeverity | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[PolicyDriftRecord]:
        results = list(self._records)
        if drift_type is not None:
            results = [r for r in results if r.drift_type == drift_type]
        if drift_severity is not None:
            results = [r for r in results if r.drift_severity == drift_severity]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        drift_id: str,
        drift_type: DriftType = DriftType.CONFIG_CHANGE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> PolicyDriftAnalysis:
        analysis = PolicyDriftAnalysis(
            drift_id=drift_id,
            drift_type=drift_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "policy_drift_detector_engine.analysis_added",
            drift_id=drift_id,
            drift_type=drift_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_drift_distribution(self) -> dict[str, Any]:
        """Analyze drift distribution by type and severity."""
        type_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.drift_type.value
            type_data.setdefault(key, {})
            sev = r.drift_severity.value
            type_data[key][sev] = type_data[key].get(sev, 0) + 1
        result: dict[str, Any] = {}
        for dtype, sevs in type_data.items():
            total = sum(sevs.values())
            crit_ct = sevs.get("critical", 0) + sevs.get("high", 0)
            result[dtype] = {
                "total": total,
                "severities": sevs,
                "critical_high_pct": (round(crit_ct / total * 100, 2) if total else 0.0),
                "above_threshold": total > self._threshold,
            }
        return result

    def identify_unresolved_drifts(self) -> list[dict[str, Any]]:
        """Identify unresolved drifts requiring manual intervention."""
        unresolved: list[dict[str, Any]] = []
        for r in self._records:
            if r.reconciliation_status in (
                ReconciliationStatus.PENDING,
                ReconciliationStatus.MANUAL_REQUIRED,
            ):
                unresolved.append(
                    {
                        "record_id": r.id,
                        "drift_id": r.drift_id,
                        "drift_type": r.drift_type.value,
                        "drift_severity": r.drift_severity.value,
                        "reconciliation_status": r.reconciliation_status.value,
                        "policy_name": r.policy_name,
                        "expected_value": r.expected_value,
                        "actual_value": r.actual_value,
                        "auto_reconcilable": r.auto_reconcilable,
                        "service": r.service,
                    }
                )
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "cosmetic": 4}
        return sorted(
            unresolved,
            key=lambda x: severity_order.get(x["drift_severity"], 5),
        )

    def detect_drift_trends(self) -> list[dict[str, Any]]:
        """Detect trends in policy drift over time."""
        buckets: dict[str, list[PolicyDriftRecord]] = {}
        for r in self._records:
            day = time.strftime("%Y-%m-%d", time.gmtime(r.created_at))
            buckets.setdefault(day, []).append(r)
        trends: list[dict[str, Any]] = []
        for day, records in sorted(buckets.items()):
            pending_ct = sum(
                1 for r in records if r.reconciliation_status == ReconciliationStatus.PENDING
            )
            auto_fixed_ct = sum(
                1 for r in records if r.reconciliation_status == ReconciliationStatus.AUTO_FIXED
            )
            trends.append(
                {
                    "date": day,
                    "total_drifts": len(records),
                    "pending": pending_ct,
                    "auto_fixed": auto_fixed_ct,
                }
            )
        return trends

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> PolicyDriftReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.drift_type.value] = by_e1.get(r.drift_type.value, 0) + 1
            by_e2[r.drift_severity.value] = by_e2.get(r.drift_severity.value, 0) + 1
            by_e3[r.reconciliation_status.value] = by_e3.get(r.reconciliation_status.value, 0) + 1
        svc_counts: dict[str, int] = {}
        for r in self._records:
            svc_counts[r.service] = svc_counts.get(r.service, 0) + 1
        avg_per_svc = round(sum(svc_counts.values()) / len(svc_counts), 2) if svc_counts else 0.0
        gap_count = sum(
            1
            for r in self._records
            if r.reconciliation_status
            in (ReconciliationStatus.PENDING, ReconciliationStatus.MANUAL_REQUIRED)
        )
        gap_list = self.identify_unresolved_drifts()
        top_gaps = [o["drift_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} unresolved policy drift(s) detected")
        if avg_per_svc > self._threshold:
            recs.append(
                f"Avg drifts per service {avg_per_svc} exceeds threshold ({self._threshold})"
            )
        if not recs:
            recs.append("Policy Drift Detector Engine is healthy")
        return PolicyDriftReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_drifts_per_service=avg_per_svc,
            by_drift_type=by_e1,
            by_drift_severity=by_e2,
            by_reconciliation_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("policy_drift_detector_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.drift_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "drift_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
