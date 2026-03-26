"""Vulnerability Remediation Analytics — measure MTTR and risk reduction."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RemediationSpeed(StrEnum):
    IMMEDIATE = "immediate"
    FAST = "fast"
    NORMAL = "normal"
    SLOW = "slow"
    OVERDUE = "overdue"


class PatchCompliance(StrEnum):
    FULLY_COMPLIANT = "fully_compliant"
    MOSTLY_COMPLIANT = "mostly_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    EXEMPT = "exempt"


class RiskReduction(StrEnum):
    CRITICAL_ELIMINATED = "critical_eliminated"
    SIGNIFICANT = "significant"
    MODERATE = "moderate"
    MINIMAL = "minimal"
    NONE = "none"


# --- Models ---


class RemediationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    cve_id: str = ""
    asset_id: str = ""
    speed: RemediationSpeed = RemediationSpeed.NORMAL
    compliance: PatchCompliance = PatchCompliance.PARTIALLY_COMPLIANT
    risk_reduction: RiskReduction = RiskReduction.MODERATE
    mttr_hours: float = 0.0
    sla_target_hours: float = 72.0
    sla_met: bool = False
    risk_score_before: float = 0.0
    risk_score_after: float = 0.0
    created_at: float = Field(default_factory=time.time)


class RemediationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    period_days: int = 30
    avg_mttr_hours: float = 0.0
    sla_compliance_pct: float = 0.0
    total_risk_reduced: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class RemediationReport(BaseModel):
    total_remediations: int = 0
    avg_mttr_hours: float = 0.0
    sla_compliance_pct: float = 0.0
    total_risk_reduction: float = 0.0
    by_speed: dict[str, int] = Field(default_factory=dict)
    by_compliance: dict[str, int] = Field(default_factory=dict)
    by_risk_reduction: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class VulnRemediationAnalytics:
    """Measure vulnerability remediation MTTR and risk reduction."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[RemediationRecord] = []
        logger.info(
            "vuln_remediation_analytics.initialized",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> RemediationRecord:
        record = RemediationRecord(**kwargs)
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "vuln_remediation_analytics.record_added",
            record_id=record.id,
            cve_id=record.cve_id,
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
            "cve_id": rec.cve_id,
            "mttr_hours": rec.mttr_hours,
        }

    # -- domain methods --

    def measure_mttr(self) -> dict[str, Any]:
        """Measure mean time to remediate across all records."""
        if not self._records:
            return {"avg_mttr_hours": 0.0, "total": 0}
        total_mttr = sum(r.mttr_hours for r in self._records)
        avg = round(total_mttr / len(self._records), 2)
        fastest = min(r.mttr_hours for r in self._records)
        slowest = max(r.mttr_hours for r in self._records)
        return {
            "avg_mttr_hours": avg,
            "fastest_hours": fastest,
            "slowest_hours": slowest,
            "total": len(self._records),
        }

    def track_sla_compliance(self) -> dict[str, Any]:
        """Track SLA compliance for remediation."""
        if not self._records:
            return {"compliance_pct": 0.0, "total": 0}
        met = sum(1 for r in self._records if r.sla_met)
        pct = round(met / len(self._records) * 100, 2)
        overdue = [
            {
                "id": r.id,
                "cve_id": r.cve_id,
                "mttr_hours": r.mttr_hours,
                "sla_target": r.sla_target_hours,
            }
            for r in self._records
            if not r.sla_met
        ]
        return {
            "compliance_pct": pct,
            "met": met,
            "missed": len(self._records) - met,
            "total": len(self._records),
            "overdue_sample": overdue[:10],
        }

    def quantify_risk_reduction(self) -> dict[str, Any]:
        """Quantify total risk reduction from remediations."""
        total_before = sum(r.risk_score_before for r in self._records)
        total_after = sum(r.risk_score_after for r in self._records)
        reduction = round(total_before - total_after, 4)
        pct = round(reduction / total_before * 100, 2) if total_before > 0 else 0.0
        return {
            "total_risk_before": round(total_before, 4),
            "total_risk_after": round(total_after, 4),
            "total_reduction": reduction,
            "reduction_pct": pct,
            "total_records": len(self._records),
        }

    # -- report / stats --

    def generate_report(self) -> RemediationReport:
        by_speed: dict[str, int] = {}
        by_comp: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        total_mttr = 0.0
        total_reduction = 0.0
        for r in self._records:
            by_speed[r.speed.value] = by_speed.get(r.speed.value, 0) + 1
            by_comp[r.compliance.value] = by_comp.get(r.compliance.value, 0) + 1
            by_risk[r.risk_reduction.value] = by_risk.get(r.risk_reduction.value, 0) + 1
            total_mttr += r.mttr_hours
            total_reduction += r.risk_score_before - r.risk_score_after
        avg_mttr = round(total_mttr / len(self._records), 2) if self._records else 0.0
        sla_met = sum(1 for r in self._records if r.sla_met)
        sla_pct = round(sla_met / len(self._records) * 100, 2) if self._records else 0.0
        recs: list[str] = []
        overdue = by_speed.get("overdue", 0)
        if overdue > 0:
            recs.append(f"{overdue} overdue remediation(s)")
        if sla_pct < 80:
            recs.append(f"SLA compliance at {sla_pct}% — below 80% target")
        if not recs:
            recs.append("Remediation metrics on target")
        return RemediationReport(
            total_remediations=len(self._records),
            avg_mttr_hours=avg_mttr,
            sla_compliance_pct=sla_pct,
            total_risk_reduction=round(total_reduction, 4),
            by_speed=by_speed,
            by_compliance=by_comp,
            by_risk_reduction=by_risk,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "sla_met": sum(1 for r in self._records if r.sla_met),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("vuln_remediation_analytics.cleared")
        return {"status": "cleared"}
