"""Hunt Lead Generator — generate and score threat hunt leads."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class LeadSource(StrEnum):
    THREAT_INTEL = "threat_intel"
    ANOMALY_DETECTION = "anomaly_detection"
    INCIDENT_PATTERN = "incident_pattern"
    HYPOTHESIS_DRIVEN = "hypothesis_driven"
    AUTOMATED_SWEEP = "automated_sweep"


class TTPCategory(StrEnum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"


class LeadPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# --- Models ---


class HuntLeadRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    lead_source: LeadSource = LeadSource.THREAT_INTEL
    ttp_category: TTPCategory = TTPCategory.INITIAL_ACCESS
    priority: LeadPriority = LeadPriority.MEDIUM
    hypothesis: str = ""
    quality_score: float = 0.0
    confirmed: bool = False
    false_positive: bool = False
    created_at: float = Field(default_factory=time.time)


class HuntLeadAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    lead_id: str = ""
    quality_factors: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    estimated_effort_hours: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class HuntLeadReport(BaseModel):
    total_leads: int = 0
    confirmed_count: int = 0
    false_positive_rate_pct: float = 0.0
    by_source: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    by_ttp: dict[str, int] = Field(default_factory=dict)
    avg_quality_score: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class HuntLeadGenerator:
    """Generate and score threat hunt leads."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[HuntLeadRecord] = []
        logger.info(
            "hunt_lead_generator.initialized",
            max_records=max_records,
        )

    def add_record(self, **kwargs: Any) -> HuntLeadRecord:
        record = HuntLeadRecord(**kwargs)
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "hunt_lead_generator.record_added",
            record_id=record.id,
            source=record.lead_source.value,
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
            "source": rec.lead_source.value,
            "priority": rec.priority.value,
            "quality_score": rec.quality_score,
        }

    # -- domain methods --

    def generate_leads(
        self,
        source: LeadSource = LeadSource.THREAT_INTEL,
        ttp_category: TTPCategory = TTPCategory.INITIAL_ACCESS,
        count: int = 5,
    ) -> list[HuntLeadRecord]:
        """Generate hunt leads from a given source and TTP."""
        leads: list[HuntLeadRecord] = []
        for i in range(count):
            score = round(0.5 + (i * 0.1), 2)
            score = min(score, 1.0)
            lead = self.add_record(
                lead_source=source,
                ttp_category=ttp_category,
                quality_score=score,
                hypothesis=f"Hunt hypothesis {i + 1} for {ttp_category.value}",
            )
            leads.append(lead)
        logger.info(
            "hunt_lead_generator.leads_generated",
            count=len(leads),
            source=source.value,
        )
        return leads

    def score_lead_quality(self, lead_id: str) -> dict[str, Any]:
        """Score the quality of a specific hunt lead."""
        record = None
        for r in self._records:
            if r.id == lead_id:
                record = r
                break
        if record is None:
            return {"found": False, "lead_id": lead_id}
        factors: list[str] = []
        score = record.quality_score
        if record.lead_source == LeadSource.THREAT_INTEL:
            score = min(score + 0.1, 1.0)
            factors.append("threat_intel_boost")
        if record.ttp_category in (
            TTPCategory.LATERAL_MOVEMENT,
            TTPCategory.PRIVILEGE_ESCALATION,
        ):
            score = min(score + 0.15, 1.0)
            factors.append("high_impact_ttp")
        record.quality_score = round(score, 4)
        if score >= 0.8:
            record.priority = LeadPriority.CRITICAL
        elif score >= 0.6:
            record.priority = LeadPriority.HIGH
        logger.info(
            "hunt_lead_generator.quality_scored",
            lead_id=lead_id,
            score=record.quality_score,
        )
        return {
            "found": True,
            "lead_id": lead_id,
            "quality_score": record.quality_score,
            "priority": record.priority.value,
            "factors": factors,
        }

    def track_lead_outcomes(self) -> dict[str, Any]:
        """Track outcomes of all hunt leads."""
        total = len(self._records)
        confirmed = sum(1 for r in self._records if r.confirmed)
        fp = sum(1 for r in self._records if r.confirmed and r.false_positive)
        fp_rate = round(fp / confirmed * 100, 2) if confirmed > 0 else 0.0
        return {
            "total_leads": total,
            "confirmed": confirmed,
            "false_positives": fp,
            "false_positive_rate_pct": fp_rate,
            "pending": total - confirmed,
        }

    # -- report / stats --

    def generate_report(self) -> HuntLeadReport:
        by_source: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        by_ttp: dict[str, int] = {}
        total_score = 0.0
        for r in self._records:
            by_source[r.lead_source.value] = by_source.get(r.lead_source.value, 0) + 1
            by_priority[r.priority.value] = by_priority.get(r.priority.value, 0) + 1
            by_ttp[r.ttp_category.value] = by_ttp.get(r.ttp_category.value, 0) + 1
            total_score += r.quality_score
        confirmed = sum(1 for r in self._records if r.confirmed)
        fp = sum(1 for r in self._records if r.confirmed and r.false_positive)
        fp_rate = round(fp / confirmed * 100, 2) if confirmed > 0 else 0.0
        avg_score = round(total_score / len(self._records), 4) if self._records else 0.0
        recs: list[str] = []
        if by_priority.get("critical", 0) > 0:
            recs.append("Critical leads require immediate attention")
        if fp_rate > 30:
            recs.append("High FP rate — refine lead generation")
        if not recs:
            recs.append("Lead generation operating normally")
        return HuntLeadReport(
            total_leads=len(self._records),
            confirmed_count=confirmed,
            false_positive_rate_pct=fp_rate,
            by_source=by_source,
            by_priority=by_priority,
            by_ttp=by_ttp,
            avg_quality_score=avg_score,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "confirmed": sum(1 for r in self._records if r.confirmed),
            "avg_quality": (
                round(
                    sum(r.quality_score for r in self._records) / len(self._records),
                    4,
                )
                if self._records
                else 0.0
            ),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("hunt_lead_generator.cleared")
        return {"status": "cleared"}
