"""Exposure Prioritization — prioritize by business context."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PriorityFactor(StrEnum):
    EXPLOITABILITY = "exploitability"
    BUSINESS_IMPACT = "business_impact"
    EXPOSURE_DURATION = "exposure_duration"
    THREAT_INTELLIGENCE = "threat_intelligence"
    COMPLIANCE_IMPACT = "compliance_impact"


class BusinessCriticality(StrEnum):
    MISSION_CRITICAL = "mission_critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NON_ESSENTIAL = "non_essential"


class RemediationEffort(StrEnum):
    TRIVIAL = "trivial"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    MAJOR_PROJECT = "major_project"


# --- Models ---


class ExposurePriorityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exposure_id: str = ""
    factor: PriorityFactor = PriorityFactor.BUSINESS_IMPACT
    criticality: BusinessCriticality = BusinessCriticality.MEDIUM
    effort: RemediationEffort = RemediationEffort.MODERATE
    asset_name: str = ""
    vulnerability: str = ""
    priority_score: float = 0.0
    days_exposed: int = 0
    remediated: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ExposurePriorityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exposure_id: str = ""
    factor: PriorityFactor = PriorityFactor.BUSINESS_IMPACT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExposurePriorityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_priority_score: float = 0.0
    unremediated_count: int = 0
    by_factor: dict[str, int] = Field(default_factory=dict)
    by_criticality: dict[str, int] = Field(default_factory=dict)
    by_effort: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ExposurePrioritizationEngine:
    """Prioritize exposures by business context."""

    def __init__(
        self,
        max_records: int = 200000,
        priority_threshold: float = 0.7,
    ) -> None:
        self._max_records = max_records
        self._threshold = priority_threshold
        self._records: list[ExposurePriorityRecord] = []
        self._analyses: list[ExposurePriorityAnalysis] = []
        logger.info(
            "exposure_prioritization.initialized",
            max_records=max_records,
            priority_threshold=priority_threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        exposure_id: str,
        factor: PriorityFactor = (PriorityFactor.BUSINESS_IMPACT),
        criticality: BusinessCriticality = (BusinessCriticality.MEDIUM),
        effort: RemediationEffort = (RemediationEffort.MODERATE),
        asset_name: str = "",
        vulnerability: str = "",
        priority_score: float = 0.0,
        days_exposed: int = 0,
        remediated: bool = False,
        service: str = "",
        team: str = "",
    ) -> ExposurePriorityRecord:
        record = ExposurePriorityRecord(
            exposure_id=exposure_id,
            factor=factor,
            criticality=criticality,
            effort=effort,
            asset_name=asset_name,
            vulnerability=vulnerability,
            priority_score=priority_score,
            days_exposed=days_exposed,
            remediated=remediated,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "exposure_prioritization.record_added",
            record_id=record.id,
            exposure_id=exposure_id,
            criticality=criticality.value,
            priority_score=priority_score,
        )
        return record

    def get_record(self, record_id: str) -> ExposurePriorityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        criticality: BusinessCriticality | None = (None),
        effort: RemediationEffort | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ExposurePriorityRecord]:
        results = list(self._records)
        if criticality is not None:
            results = [r for r in results if r.criticality == criticality]
        if effort is not None:
            results = [r for r in results if r.effort == effort]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, exposure_id: str) -> ExposurePriorityAnalysis:
        matched = [r for r in self._records if r.exposure_id == exposure_id]
        scores = [r.priority_score for r in matched]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        breached = avg > self._threshold
        analysis = ExposurePriorityAnalysis(
            exposure_id=exposure_id,
            factor=(matched[-1].factor if matched else PriorityFactor.BUSINESS_IMPACT),
            analysis_score=avg,
            threshold=self._threshold,
            breached=breached,
            description=(f"Priority {avg} for {exposure_id}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ------------------------------------

    def calculate_priority_score(
        self,
        exposure_id: str,
        criticality: BusinessCriticality,
        effort: RemediationEffort,
        days_exposed: int = 0,
    ) -> dict[str, Any]:
        """Calculate priority score for exposure."""
        crit_weights = {
            BusinessCriticality.MISSION_CRITICAL: 1.0,
            BusinessCriticality.HIGH: 0.8,
            BusinessCriticality.MEDIUM: 0.5,
            BusinessCriticality.LOW: 0.3,
            BusinessCriticality.NON_ESSENTIAL: 0.1,
        }
        effort_weights = {
            RemediationEffort.TRIVIAL: 1.0,
            RemediationEffort.LOW: 0.8,
            RemediationEffort.MODERATE: 0.5,
            RemediationEffort.HIGH: 0.3,
            RemediationEffort.MAJOR_PROJECT: 0.1,
        }
        crit_w = crit_weights.get(criticality, 0.5)
        eff_w = effort_weights.get(effort, 0.5)
        age_factor = min(1.0, days_exposed / 90)
        score = round(
            crit_w * 0.5 + eff_w * 0.3 + age_factor * 0.2,
            4,
        )
        record = self.add_record(
            exposure_id=exposure_id,
            criticality=criticality,
            effort=effort,
            priority_score=score,
            days_exposed=days_exposed,
        )
        return {
            "record_id": record.id,
            "exposure_id": exposure_id,
            "priority_score": score,
            "criticality": criticality.value,
            "effort": effort.value,
            "days_exposed": days_exposed,
        }

    def rank_exposures(
        self,
    ) -> list[dict[str, Any]]:
        """Rank all exposures by priority."""
        unremediated = [r for r in self._records if not r.remediated]
        ranked: list[dict[str, Any]] = []
        for r in unremediated:
            ranked.append(
                {
                    "record_id": r.id,
                    "exposure_id": r.exposure_id,
                    "asset_name": r.asset_name,
                    "criticality": r.criticality.value,
                    "effort": r.effort.value,
                    "priority_score": r.priority_score,
                    "days_exposed": r.days_exposed,
                }
            )
        ranked.sort(
            key=lambda x: x["priority_score"],
            reverse=True,
        )
        return ranked

    def generate_remediation_plan(
        self,
    ) -> dict[str, Any]:
        """Generate a remediation plan."""
        ranked = self.rank_exposures()
        quick_wins = [
            r
            for r in ranked
            if r["effort"]
            in (
                RemediationEffort.TRIVIAL.value,
                RemediationEffort.LOW.value,
            )
            and r["priority_score"] > 0.5
        ]
        critical = [
            r for r in ranked if r["criticality"] == BusinessCriticality.MISSION_CRITICAL.value
        ]
        total_unrem = sum(1 for r in self._records if not r.remediated)
        return {
            "total_unremediated": total_unrem,
            "quick_wins": len(quick_wins),
            "critical_exposures": len(critical),
            "top_10_priorities": ranked[:10],
            "quick_win_list": quick_wins[:5],
        }

    # -- report / stats ----------------------------------------

    def generate_report(
        self,
    ) -> ExposurePriorityReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.factor.value] = by_e1.get(r.factor.value, 0) + 1
            by_e2[r.criticality.value] = by_e2.get(r.criticality.value, 0) + 1
            by_e3[r.effort.value] = by_e3.get(r.effort.value, 0) + 1
        scores = [r.priority_score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        unrem = sum(1 for r in self._records if not r.remediated)
        gap_count = sum(
            1 for r in self._records if r.priority_score > self._threshold and not r.remediated
        )
        top_gaps = [
            r.exposure_id
            for r in self._records
            if r.priority_score > self._threshold and not r.remediated
        ][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} high-priority unremediated exposure(s)")
        if unrem > 0:
            recs.append(f"{unrem} total unremediated")
        if not recs:
            recs.append("Exposure Prioritization healthy")
        return ExposurePriorityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_priority_score=avg,
            unremediated_count=unrem,
            by_factor=by_e1,
            by_criticality=by_e2,
            by_effort=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("exposure_prioritization.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.criticality.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "criticality_distribution": e1_dist,
            "unremediated": sum(1 for r in self._records if not r.remediated),
            "unique_teams": len({r.team for r in self._records}),
        }
