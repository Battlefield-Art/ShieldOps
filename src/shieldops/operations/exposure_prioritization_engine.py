"""ExposurePrioritizationEngine — Prioritize exposures by CVSS, EPSS, and business context."""

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
    CVSS = "cvss"
    EPSS = "epss"
    BUSINESS_CONTEXT = "business_context"
    EXPLOIT_MATURITY = "exploit_maturity"


class BusinessCriticality(StrEnum):
    MISSION_CRITICAL = "mission_critical"
    BUSINESS_CRITICAL = "business_critical"
    OPERATIONAL = "operational"
    NON_CRITICAL = "non_critical"


class RemediationEffort(StrEnum):
    TRIVIAL = "trivial"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    COMPLEX = "complex"


# --- Models ---


class PrioritizationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    priority_factor: PriorityFactor = PriorityFactor.CVSS
    business_criticality: BusinessCriticality = BusinessCriticality.OPERATIONAL
    remediation_effort: RemediationEffort = RemediationEffort.MEDIUM
    score: float = 0.0
    cvss_score: float = 0.0
    epss_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class PrioritizationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    priority_factor: PriorityFactor = PriorityFactor.CVSS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PrioritizationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_priority_factor: dict[str, int] = Field(default_factory=dict)
    by_business_criticality: dict[str, int] = Field(default_factory=dict)
    by_remediation_effort: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ExposurePrioritizationEngine:
    """Prioritize exposures by CVSS, EPSS, and business context."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[PrioritizationRecord] = []
        self._analyses: list[PrioritizationAnalysis] = []
        logger.info(
            "exposure_prioritization_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        name: str,
        priority_factor: PriorityFactor = PriorityFactor.CVSS,
        business_criticality: BusinessCriticality = (BusinessCriticality.OPERATIONAL),
        remediation_effort: RemediationEffort = (RemediationEffort.MEDIUM),
        score: float = 0.0,
        cvss_score: float = 0.0,
        epss_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> PrioritizationRecord:
        record = PrioritizationRecord(
            name=name,
            priority_factor=priority_factor,
            business_criticality=business_criticality,
            remediation_effort=remediation_effort,
            score=score,
            cvss_score=cvss_score,
            epss_score=epss_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "exposure_prioritization_engine.record_added",
            record_id=record.id,
            name=name,
            priority_factor=priority_factor.value,
            business_criticality=business_criticality.value,
        )
        return record

    def get_record(self, record_id: str) -> PrioritizationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        priority_factor: PriorityFactor | None = None,
        business_criticality: BusinessCriticality | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[PrioritizationRecord]:
        results = list(self._records)
        if priority_factor is not None:
            results = [r for r in results if r.priority_factor == priority_factor]
        if business_criticality is not None:
            results = [r for r in results if r.business_criticality == business_criticality]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        priority_factor: PriorityFactor = PriorityFactor.CVSS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> PrioritizationAnalysis:
        analysis = PrioritizationAnalysis(
            name=name,
            priority_factor=priority_factor,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "exposure_prioritization_engine.analysis_added",
            name=name,
            priority_factor=priority_factor.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations -------------------------------------

    def calculate_priority_score(self) -> list[dict[str, Any]]:
        """Calculate composite priority score for all records."""
        crit_weights = {
            BusinessCriticality.MISSION_CRITICAL: 1.0,
            BusinessCriticality.BUSINESS_CRITICAL: 0.8,
            BusinessCriticality.OPERATIONAL: 0.5,
            BusinessCriticality.NON_CRITICAL: 0.2,
        }
        results: list[dict[str, Any]] = []
        for r in self._records:
            biz_weight = crit_weights.get(r.business_criticality, 0.5)
            composite = round(
                (r.cvss_score * 0.4 + r.epss_score * 100 * 0.3 + r.score * 0.3) * biz_weight,
                2,
            )
            results.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "cvss_score": r.cvss_score,
                    "epss_score": r.epss_score,
                    "business_criticality": (r.business_criticality.value),
                    "composite_priority": composite,
                    "urgency": (
                        "immediate"
                        if composite >= 7.0
                        else (
                            "high"
                            if composite >= 5.0
                            else ("medium" if composite >= 3.0 else "low")
                        )
                    ),
                }
            )
        return sorted(
            results,
            key=lambda x: x["composite_priority"],
            reverse=True,
        )

    def rank_exposures(self) -> list[dict[str, Any]]:
        """Rank exposures by combined risk."""
        ranked = self.calculate_priority_score()
        for i, item in enumerate(ranked):
            item["rank"] = i + 1
            record = next(
                (r for r in self._records if r.id == item["record_id"]),
                None,
            )
            if record:
                item["remediation_effort"] = record.remediation_effort.value
        return ranked

    def generate_remediation_plan(self) -> list[dict[str, Any]]:
        """Generate prioritized remediation plan."""
        effort_hours = {
            RemediationEffort.TRIVIAL: 1,
            RemediationEffort.LOW: 4,
            RemediationEffort.MEDIUM: 16,
            RemediationEffort.HIGH: 40,
            RemediationEffort.COMPLEX: 80,
        }
        ranked = self.calculate_priority_score()
        plan: list[dict[str, Any]] = []
        for i, item in enumerate(ranked):
            record = next(
                (r for r in self._records if r.id == item["record_id"]),
                None,
            )
            if not record:
                continue
            hours = effort_hours.get(record.remediation_effort, 16)
            plan.append(
                {
                    "priority": i + 1,
                    "name": item["name"],
                    "composite_priority": item["composite_priority"],
                    "urgency": item["urgency"],
                    "remediation_effort": (record.remediation_effort.value),
                    "estimated_hours": hours,
                    "service": record.service,
                    "team": record.team,
                    "action": (
                        "Patch immediately"
                        if item["urgency"] == "immediate"
                        else (
                            "Schedule this sprint"
                            if item["urgency"] == "high"
                            else "Add to backlog"
                        )
                    ),
                }
            )
        return plan

    # -- standard methods --------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.priority_factor.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "priority_factor": r.priority_factor.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats ----------------------------------------

    def generate_report(self) -> PrioritizationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.priority_factor.value] = by_e1.get(r.priority_factor.value, 0) + 1
            by_e2[r.business_criticality.value] = by_e2.get(r.business_criticality.value, 0) + 1
            by_e3[r.remediation_effort.value] = by_e3.get(r.remediation_effort.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Exposure Prioritization Engine is healthy")
        return PrioritizationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_priority_factor=by_e1,
            by_business_criticality=by_e2,
            by_remediation_effort=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("exposure_prioritization_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.priority_factor.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "priority_factor_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
