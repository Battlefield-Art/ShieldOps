"""SLAEnforcementEngine — monitor and enforce SLAs."""

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
    PLATINUM = "platinum"
    GOLD = "gold"
    SILVER = "silver"
    BRONZE = "bronze"


class EscalationStep(StrEnum):
    NONE = "none"
    NOTIFY = "notify"
    ESCALATE_L1 = "escalate_l1"
    ESCALATE_L2 = "escalate_l2"
    EXECUTIVE = "executive"


class BreachConsequence(StrEnum):
    WARNING = "warning"
    CREDIT = "credit"
    PENALTY = "penalty"
    CONTRACT_REVIEW = "contract_review"


# --- Models ---


class SLAEnforcementRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    sla_tier: SLATier = SLATier.SILVER
    escalation_step: EscalationStep = EscalationStep.NONE
    breach_consequence: BreachConsequence = BreachConsequence.WARNING
    score: float = 0.0
    target_hours: float = 24.0
    elapsed_hours: float = 0.0
    breached: bool = False
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SLAEnforcementAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    sla_tier: SLATier = SLATier.SILVER
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SLAEnforcementReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_sla_tier: dict[str, int] = Field(default_factory=dict)
    by_escalation_step: dict[str, int] = Field(default_factory=dict)
    by_breach_consequence: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class SLAEnforcementEngine:
    """Monitor and enforce SLA compliance."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[SLAEnforcementRecord] = []
        self._analyses: list[SLAEnforcementAnalysis] = []
        logger.info(
            "sla_enforcement_engine.init",
            max_records=max_records,
        )

    def record_item(
        self,
        name: str,
        sla_tier: SLATier = SLATier.SILVER,
        escalation_step: EscalationStep = (EscalationStep.NONE),
        breach_consequence: BreachConsequence = (BreachConsequence.WARNING),
        score: float = 0.0,
        target_hours: float = 24.0,
        elapsed_hours: float = 0.0,
        breached: bool = False,
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> SLAEnforcementRecord:
        record = SLAEnforcementRecord(
            name=name,
            sla_tier=sla_tier,
            escalation_step=escalation_step,
            breach_consequence=breach_consequence,
            score=score,
            target_hours=target_hours,
            elapsed_hours=elapsed_hours,
            breached=breached,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "sla_enforcement.item_recorded",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> SLAEnforcementRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        sla_tier: SLATier | None = None,
        escalation_step: (EscalationStep | None) = None,
        limit: int = 50,
    ) -> list[SLAEnforcementRecord]:
        results = list(self._records)
        if sla_tier is not None:
            results = [r for r in results if r.sla_tier == sla_tier]
        if escalation_step is not None:
            results = [r for r in results if r.escalation_step == escalation_step]
        return results[-limit:]

    # -- domain methods ---

    def monitor_sla(
        self,
    ) -> list[dict[str, Any]]:
        """Monitor SLA status per service."""
        svc_data: dict[str, list[SLAEnforcementRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service or r.name, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, recs in svc_data.items():
            breached = sum(1 for r in recs if r.breached)
            results.append(
                {
                    "service": svc,
                    "total": len(recs),
                    "breached": breached,
                    "compliance_pct": round(
                        (len(recs) - breached) / len(recs) * 100,
                        1,
                    ),
                    "tier": recs[-1].sla_tier.value,
                }
            )
        return sorted(
            results,
            key=lambda x: x["compliance_pct"],
        )

    def trigger_escalation(
        self,
    ) -> list[dict[str, Any]]:
        """Identify items needing escalation."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.breached and r.escalation_step in (
                EscalationStep.NONE,
                EscalationStep.NOTIFY,
            ):
                pct = round(
                    r.elapsed_hours / max(r.target_hours, 1) * 100,
                    1,
                )
                results.append(
                    {
                        "name": r.name,
                        "service": r.service,
                        "elapsed_pct": pct,
                        "current_step": (r.escalation_step.value),
                        "recommended": ("escalate_l1" if pct < 150 else "escalate_l2"),
                    }
                )
        return sorted(
            results,
            key=lambda x: x["elapsed_pct"],
            reverse=True,
        )

    def measure_compliance(
        self,
    ) -> dict[str, Any]:
        """Measure overall SLA compliance."""
        if not self._records:
            return {
                "total": 0,
                "compliance_pct": 100.0,
            }
        total = len(self._records)
        breached = sum(1 for r in self._records if r.breached)
        tier_compliance: dict[str, float] = {}
        tier_data: dict[str, list[SLAEnforcementRecord]] = {}
        for r in self._records:
            tier_data.setdefault(r.sla_tier.value, []).append(r)
        for tier, recs in tier_data.items():
            b = sum(1 for r in recs if r.breached)
            tier_compliance[tier] = round(
                (len(recs) - b) / len(recs) * 100,
                1,
            )
        return {
            "total": total,
            "breached": breached,
            "compliance_pct": round(
                (total - breached) / total * 100,
                1,
            ),
            "by_tier": tier_compliance,
        }

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
        }

    def generate_report(
        self,
    ) -> SLAEnforcementReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.sla_tier.value] = by_e1.get(r.sla_tier.value, 0) + 1
            by_e2[r.escalation_step.value] = by_e2.get(r.escalation_step.value, 0) + 1
            by_e3[r.breach_consequence.value] = by_e3.get(r.breach_consequence.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gaps = [r.name for r in self._records if r.score < self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("SLA enforcement is healthy")
        return SLAEnforcementReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_sla_tier=by_e1,
            by_escalation_step=by_e2,
            by_breach_consequence=by_e3,
            top_gaps=gaps,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.sla_tier.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "tier_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("sla_enforcement_engine.cleared")
        return {"status": "cleared"}
