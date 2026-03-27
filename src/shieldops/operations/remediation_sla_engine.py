"""Remediation SLA Engine — track SLA compliance."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SLATier(StrEnum):
    P1_CRITICAL = "p1_critical"
    P2_HIGH = "p2_high"
    P3_MEDIUM = "p3_medium"
    P4_LOW = "p4_low"
    P5_INFORMATIONAL = "p5_informational"


class ComplianceStatus(StrEnum):
    COMPLIANT = "compliant"
    AT_RISK = "at_risk"
    BREACHED = "breached"
    WAIVED = "waived"
    PENDING = "pending"


class EscalationLevel(StrEnum):
    NONE = "none"
    TEAM_LEAD = "team_lead"
    MANAGER = "manager"
    DIRECTOR = "director"
    VP = "vp"


# --- Models ---


class RemediationSLARecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    remediation_id: str = ""
    tier: SLATier = SLATier.P3_MEDIUM
    status: ComplianceStatus = ComplianceStatus.PENDING
    escalation: EscalationLevel = EscalationLevel.NONE
    target_hours: float = 72.0
    elapsed_hours: float = 0.0
    owner: str = ""
    created_at: float = Field(default_factory=time.time)


class RemediationSLAAnalysis(BaseModel):
    remediation_id: str = ""
    tier: str = ""
    remaining_hours: float = 0.0
    status: str = ""
    escalation_needed: bool = False
    analyzed_at: float = Field(default_factory=time.time)


class RemediationSLAReport(BaseModel):
    total_tracked: int = 0
    compliance_rate_pct: float = 0.0
    breached_count: int = 0
    at_risk_count: int = 0
    by_tier: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class RemediationSLAEngine:
    """Track remediation SLA compliance."""

    def __init__(self, max_records: int = 10000) -> None:
        self._max = max_records
        self._records: list[RemediationSLARecord] = []
        logger.info(
            "remediation_sla_engine.init",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> RemediationSLARecord:
        rec = RemediationSLARecord(**kwargs)
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "remediation_sla.recorded",
            record_id=rec.id,
        )
        return rec

    def process(self, remediation_id: str) -> RemediationSLAAnalysis:
        recs = [r for r in self._records if r.remediation_id == remediation_id]
        if not recs:
            return RemediationSLAAnalysis(remediation_id=remediation_id)
        latest = recs[-1]
        remaining = max(
            0.0,
            latest.target_hours - latest.elapsed_hours,
        )
        pct_used = (latest.elapsed_hours / latest.target_hours) if latest.target_hours > 0 else 1.0
        if pct_used >= 1.0:
            status = "breached"
        elif pct_used >= 0.8:
            status = "at_risk"
        else:
            status = "compliant"
        esc = pct_used >= 0.9
        return RemediationSLAAnalysis(
            remediation_id=remediation_id,
            tier=latest.tier.value,
            remaining_hours=round(remaining, 2),
            status=status,
            escalation_needed=esc,
        )

    def generate_report(
        self,
    ) -> RemediationSLAReport:
        by_tier: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for r in self._records:
            t = r.tier.value
            by_tier[t] = by_tier.get(t, 0) + 1
            s = r.status.value
            by_status[s] = by_status.get(s, 0) + 1
        total = len(self._records)
        compliant = sum(1 for r in self._records if r.status == ComplianceStatus.COMPLIANT)
        breached = sum(1 for r in self._records if r.status == ComplianceStatus.BREACHED)
        at_risk = sum(1 for r in self._records if r.status == ComplianceStatus.AT_RISK)
        rate = round(compliant / total * 100, 2) if total else 0.0
        recs: list[str] = []
        if breached > 0:
            recs.append(f"{breached} SLA breach(es)")
        if at_risk > 0:
            recs.append(f"{at_risk} at risk of breach")
        if not recs:
            recs.append("All SLAs compliant")
        return RemediationSLAReport(
            total_tracked=total,
            compliance_rate_pct=rate,
            breached_count=breached,
            at_risk_count=at_risk,
            by_tier=by_tier,
            by_status=by_status,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max,
            "unique_remediations": len({r.remediation_id for r in self._records}),
        }

    def clear_data(self) -> None:
        self._records.clear()
        logger.info("remediation_sla.cleared")

    # -- domain methods --

    def track_sla(
        self,
        remediation_id: str,
        tier: SLATier,
        target_hours: float = 72.0,
        elapsed_hours: float = 0.0,
        owner: str = "",
    ) -> RemediationSLARecord:
        """Start tracking SLA for a remediation."""
        pct = (elapsed_hours / target_hours) if target_hours > 0 else 1.0
        if pct >= 1.0:
            status = ComplianceStatus.BREACHED
        elif pct >= 0.8:
            status = ComplianceStatus.AT_RISK
        else:
            status = ComplianceStatus.COMPLIANT
        return self.add_record(
            remediation_id=remediation_id,
            tier=tier,
            target_hours=target_hours,
            elapsed_hours=elapsed_hours,
            status=status,
            owner=owner,
        )

    def measure_compliance(
        self,
        tier: SLATier | None = None,
    ) -> dict[str, Any]:
        """Measure SLA compliance rate."""
        recs = self._records
        if tier:
            recs = [r for r in recs if r.tier == tier]
        total = len(recs)
        compliant = sum(1 for r in recs if r.status == ComplianceStatus.COMPLIANT)
        rate = round(compliant / total * 100, 2) if total else 0.0
        return {
            "tier": tier.value if tier else "all",
            "total": total,
            "compliant": compliant,
            "compliance_rate_pct": rate,
        }

    def trigger_escalation(self, remediation_id: str) -> dict[str, Any]:
        """Escalate a breached or at-risk SLA."""
        recs = [r for r in self._records if r.remediation_id == remediation_id]
        if not recs:
            return {
                "found": False,
                "remediation_id": remediation_id,
            }
        latest = recs[-1]
        levels = list(EscalationLevel)
        idx = levels.index(latest.escalation)
        if idx < len(levels) - 1:
            latest.escalation = levels[idx + 1]
        logger.info(
            "remediation_sla.escalated",
            remediation_id=remediation_id,
            level=latest.escalation.value,
        )
        return {
            "found": True,
            "remediation_id": remediation_id,
            "escalation": latest.escalation.value,
            "tier": latest.tier.value,
        }
