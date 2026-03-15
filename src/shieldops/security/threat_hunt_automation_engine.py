"""Threat Hunt Automation Engine —
auto-trigger threat hunts based on RBA risk scores and MITRE ATT&CK coverage gaps."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class HuntTrigger(StrEnum):
    RBA_SCORE = "rba_score"
    MITRE_GAP = "mitre_gap"
    INTEL_FEED = "intel_feed"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"


class HuntPriority(StrEnum):
    IMMEDIATE = "immediate"
    HIGH = "high"
    SCHEDULED = "scheduled"
    BACKGROUND = "background"


class HuntOutcome(StrEnum):
    CONFIRMED_THREAT = "confirmed_threat"
    FALSE_POSITIVE = "false_positive"
    INCONCLUSIVE = "inconclusive"
    NEEDS_ESCALATION = "needs_escalation"


# --- Models ---


class ThreatHuntRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""
    hunt_trigger: HuntTrigger = HuntTrigger.RBA_SCORE
    hunt_priority: HuntPriority = HuntPriority.SCHEDULED
    hunt_outcome: HuntOutcome = HuntOutcome.INCONCLUSIVE
    risk_score: float = 0.0
    mitre_tactic: str = ""
    mitre_technique: str = ""
    hypothesis: str = ""
    findings: list[str] = Field(default_factory=list)
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ThreatHuntAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""
    hunt_trigger: HuntTrigger = HuntTrigger.RBA_SCORE
    hunt_priority: HuntPriority = HuntPriority.SCHEDULED
    recommended_action: str = ""
    risk_assessment: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ThreatHuntReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    confirmed_threat_rate: float = 0.0
    by_hunt_trigger: dict[str, int] = Field(default_factory=dict)
    by_hunt_priority: dict[str, int] = Field(default_factory=dict)
    by_hunt_outcome: dict[str, int] = Field(default_factory=dict)
    high_risk_entities: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ThreatHuntAutomationEngine:
    """Auto-trigger threat hunts based on RBA risk scores
    and MITRE ATT&CK coverage gaps."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ThreatHuntRecord] = []
        self._analyses: dict[str, ThreatHuntAnalysis] = {}
        logger.info("threat_hunt_automation_engine.init", max_records=max_records)

    def add_record(
        self,
        entity_id: str = "",
        hunt_trigger: HuntTrigger = HuntTrigger.RBA_SCORE,
        hunt_priority: HuntPriority = HuntPriority.SCHEDULED,
        hunt_outcome: HuntOutcome = HuntOutcome.INCONCLUSIVE,
        risk_score: float = 0.0,
        mitre_tactic: str = "",
        mitre_technique: str = "",
        hypothesis: str = "",
        findings: list[str] | None = None,
        description: str = "",
    ) -> ThreatHuntRecord:
        record = ThreatHuntRecord(
            entity_id=entity_id,
            hunt_trigger=hunt_trigger,
            hunt_priority=hunt_priority,
            hunt_outcome=hunt_outcome,
            risk_score=risk_score,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            hypothesis=hypothesis,
            findings=findings or [],
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "threat_hunt.record_added",
            record_id=record.id,
            entity_id=entity_id,
        )
        return record

    def process(self, key: str) -> ThreatHuntAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        risk_assessment = round(rec.risk_score * 100, 2)
        if rec.risk_score >= 0.8:
            priority = HuntPriority.IMMEDIATE
            action = "Initiate immediate threat hunt"
        elif rec.risk_score >= 0.5:
            priority = HuntPriority.HIGH
            action = "Schedule high-priority hunt"
        else:
            priority = rec.hunt_priority
            action = "Continue monitoring"
        analysis = ThreatHuntAnalysis(
            entity_id=rec.entity_id,
            hunt_trigger=rec.hunt_trigger,
            hunt_priority=priority,
            recommended_action=action,
            risk_assessment=risk_assessment,
            description=(f"Entity {rec.entity_id} risk={risk_assessment}%"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ThreatHuntReport:
        by_trigger: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        for r in self._records:
            by_trigger[r.hunt_trigger.value] = by_trigger.get(r.hunt_trigger.value, 0) + 1
            by_priority[r.hunt_priority.value] = by_priority.get(r.hunt_priority.value, 0) + 1
            by_outcome[r.hunt_outcome.value] = by_outcome.get(r.hunt_outcome.value, 0) + 1
        confirmed = sum(1 for r in self._records if r.hunt_outcome == HuntOutcome.CONFIRMED_THREAT)
        threat_rate = round(confirmed / len(self._records) * 100, 2) if self._records else 0.0
        high_risk = list(
            {r.entity_id for r in self._records if r.risk_score > 0.7 and r.entity_id}
        )[:10]
        recs: list[str] = []
        if high_risk:
            recs.append(f"{len(high_risk)} entities exceed risk threshold")
        if threat_rate > 30:
            recs.append("High confirmed threat rate — increase hunt cadence")
        if not recs:
            recs.append("Threat hunt automation operating normally")
        return ThreatHuntReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            confirmed_threat_rate=threat_rate,
            by_hunt_trigger=by_trigger,
            by_hunt_priority=by_priority,
            by_hunt_outcome=by_outcome,
            high_risk_entities=high_risk,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        trigger_dist: dict[str, int] = {}
        for r in self._records:
            trigger_dist[r.hunt_trigger.value] = trigger_dist.get(r.hunt_trigger.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "hunt_trigger_distribution": trigger_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("threat_hunt_automation_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def auto_trigger_hunts(self, risk_threshold: float = 0.7) -> list[dict[str, Any]]:
        """Identify entities that need proactive hunting based on
        RBA risk scores and MITRE coverage gaps."""
        entity_data: dict[str, list[ThreatHuntRecord]] = {}
        for r in self._records:
            entity_data.setdefault(r.entity_id, []).append(r)
        results: list[dict[str, Any]] = []
        for eid, recs in entity_data.items():
            max_risk = max(r.risk_score for r in recs)
            mitre_tactics = {r.mitre_tactic for r in recs if r.mitre_tactic}
            has_gaps = len(mitre_tactics) < 3
            if max_risk >= risk_threshold or has_gaps:
                priority = (
                    HuntPriority.IMMEDIATE
                    if max_risk >= 0.9
                    else HuntPriority.HIGH
                    if max_risk >= risk_threshold
                    else HuntPriority.SCHEDULED
                )
                results.append(
                    {
                        "entity_id": eid,
                        "max_risk_score": max_risk,
                        "mitre_tactics_observed": len(mitre_tactics),
                        "has_coverage_gaps": has_gaps,
                        "recommended_priority": priority.value,
                        "hunt_count": len(recs),
                    }
                )
        results.sort(key=lambda x: x["max_risk_score"], reverse=True)
        return results

    def correlate_hunt_to_rba(self) -> list[dict[str, Any]]:
        """Correlate hunt findings back to RBA risk scores."""
        entity_hunts: dict[str, list[ThreatHuntRecord]] = {}
        for r in self._records:
            entity_hunts.setdefault(r.entity_id, []).append(r)
        results: list[dict[str, Any]] = []
        for eid, recs in entity_hunts.items():
            avg_risk = round(sum(r.risk_score for r in recs) / len(recs), 4)
            confirmed = sum(1 for r in recs if r.hunt_outcome == HuntOutcome.CONFIRMED_THREAT)
            false_pos = sum(1 for r in recs if r.hunt_outcome == HuntOutcome.FALSE_POSITIVE)
            correlation = (
                "strong"
                if confirmed > 0 and avg_risk > 0.7
                else ("weak" if false_pos > confirmed else "moderate")
            )
            results.append(
                {
                    "entity_id": eid,
                    "avg_risk_score": avg_risk,
                    "confirmed_threats": confirmed,
                    "false_positives": false_pos,
                    "total_hunts": len(recs),
                    "rba_correlation": correlation,
                }
            )
        results.sort(key=lambda x: x["avg_risk_score"], reverse=True)
        return results

    def measure_hunt_effectiveness(self) -> dict[str, Any]:
        """Track confirmed threat rate and effectiveness across hunts."""
        if not self._records:
            return {
                "total_hunts": 0,
                "confirmed_rate": 0.0,
                "false_positive_rate": 0.0,
                "escalation_rate": 0.0,
                "effectiveness_grade": "no_data",
            }
        total = len(self._records)
        confirmed = sum(1 for r in self._records if r.hunt_outcome == HuntOutcome.CONFIRMED_THREAT)
        false_pos = sum(1 for r in self._records if r.hunt_outcome == HuntOutcome.FALSE_POSITIVE)
        escalated = sum(1 for r in self._records if r.hunt_outcome == HuntOutcome.NEEDS_ESCALATION)
        confirmed_rate = round(confirmed / total * 100, 2)
        fp_rate = round(false_pos / total * 100, 2)
        esc_rate = round(escalated / total * 100, 2)
        if confirmed_rate >= 30:
            grade = "excellent"
        elif confirmed_rate >= 15:
            grade = "good"
        elif confirmed_rate >= 5:
            grade = "fair"
        else:
            grade = "poor"
        return {
            "total_hunts": total,
            "confirmed_rate": confirmed_rate,
            "false_positive_rate": fp_rate,
            "escalation_rate": esc_rate,
            "effectiveness_grade": grade,
        }
