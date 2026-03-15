"""OperationalMaturityEngine — Assess and track operational maturity across SRE practice."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MaturityDomain(StrEnum):
    INCIDENT_MANAGEMENT = "incident_management"
    MONITORING = "monitoring"
    AUTOMATION = "automation"
    LEARNING = "learning"
    SECURITY = "security"


class MaturityLevel(StrEnum):
    AD_HOC = "ad_hoc"
    REPEATABLE = "repeatable"
    DEFINED = "defined"
    MANAGED = "managed"
    OPTIMIZED = "optimized"


class AssessmentConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# --- Models ---


class OperationalMaturityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    maturity_domain: MaturityDomain = MaturityDomain.INCIDENT_MANAGEMENT
    maturity_level: MaturityLevel = MaturityLevel.AD_HOC
    assessment_confidence: AssessmentConfidence = AssessmentConfidence.MEDIUM
    score: float = 0.0
    practice_count: int = 0
    automated_pct: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OperationalMaturityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    maturity_domain: MaturityDomain = MaturityDomain.INCIDENT_MANAGEMENT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OperationalMaturityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_maturity_domain: dict[str, int] = Field(default_factory=dict)
    by_maturity_level: dict[str, int] = Field(default_factory=dict)
    by_assessment_confidence: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OperationalMaturityEngine:
    """Assess and track operational maturity across the SRE practice."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OperationalMaturityRecord] = []
        self._analyses: list[OperationalMaturityAnalysis] = []
        logger.info(
            "operational_maturity_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        maturity_domain: MaturityDomain = MaturityDomain.INCIDENT_MANAGEMENT,
        maturity_level: MaturityLevel = MaturityLevel.AD_HOC,
        assessment_confidence: AssessmentConfidence = AssessmentConfidence.MEDIUM,
        score: float = 0.0,
        practice_count: int = 0,
        automated_pct: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> OperationalMaturityRecord:
        record = OperationalMaturityRecord(
            name=name,
            maturity_domain=maturity_domain,
            maturity_level=maturity_level,
            assessment_confidence=assessment_confidence,
            score=score,
            practice_count=practice_count,
            automated_pct=automated_pct,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "operational_maturity_engine.record_added",
            record_id=record.id,
            name=name,
            maturity_domain=maturity_domain.value,
            maturity_level=maturity_level.value,
        )
        return record

    def get_record(self, record_id: str) -> OperationalMaturityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        maturity_domain: MaturityDomain | None = None,
        maturity_level: MaturityLevel | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[OperationalMaturityRecord]:
        results = list(self._records)
        if maturity_domain is not None:
            results = [r for r in results if r.maturity_domain == maturity_domain]
        if maturity_level is not None:
            results = [r for r in results if r.maturity_level == maturity_level]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        maturity_domain: MaturityDomain = MaturityDomain.INCIDENT_MANAGEMENT,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> OperationalMaturityAnalysis:
        analysis = OperationalMaturityAnalysis(
            name=name,
            maturity_domain=maturity_domain,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "operational_maturity_engine.analysis_added",
            name=name,
            maturity_domain=maturity_domain.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_maturity_score(self) -> list[dict[str, Any]]:
        """Compute maturity score per domain and team."""
        level_scores = {
            MaturityLevel.AD_HOC: 1,
            MaturityLevel.REPEATABLE: 2,
            MaturityLevel.DEFINED: 3,
            MaturityLevel.MANAGED: 4,
            MaturityLevel.OPTIMIZED: 5,
        }
        domain_data: dict[str, list[OperationalMaturityRecord]] = {}
        for r in self._records:
            domain_data.setdefault(r.maturity_domain.value, []).append(r)
        results: list[dict[str, Any]] = []
        for domain, records in domain_data.items():
            levels = [level_scores.get(r.maturity_level, 1) for r in records]
            avg_level = round(sum(levels) / len(levels), 2)
            avg_score = round(sum(r.score for r in records) / len(records), 2)
            avg_automation = round(sum(r.automated_pct for r in records) / len(records), 1)
            results.append(
                {
                    "domain": domain,
                    "assessment_count": len(records),
                    "avg_maturity_level": avg_level,
                    "avg_score": avg_score,
                    "avg_automation_pct": avg_automation,
                    "maturity_label": (
                        "optimized"
                        if avg_level >= 4.5
                        else "managed"
                        if avg_level >= 3.5
                        else "defined"
                        if avg_level >= 2.5
                        else "repeatable"
                        if avg_level >= 1.5
                        else "ad_hoc"
                    ),
                }
            )
        return sorted(results, key=lambda x: x["avg_maturity_level"])

    def identify_maturity_gaps(self) -> list[dict[str, Any]]:
        """Identify domains and teams with low maturity levels."""
        gaps: list[dict[str, Any]] = []
        low_maturity = [
            r
            for r in self._records
            if r.maturity_level in (MaturityLevel.AD_HOC, MaturityLevel.REPEATABLE)
        ]
        for r in low_maturity:
            gaps.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "team": r.team,
                    "domain": r.maturity_domain.value,
                    "maturity_level": r.maturity_level.value,
                    "score": r.score,
                    "automated_pct": r.automated_pct,
                }
            )
        return sorted(gaps, key=lambda x: x["score"])

    def recommend_maturity_roadmap(self) -> list[dict[str, Any]]:
        """Recommend steps to improve operational maturity."""
        level_next = {
            MaturityLevel.AD_HOC: "repeatable",
            MaturityLevel.REPEATABLE: "defined",
            MaturityLevel.DEFINED: "managed",
            MaturityLevel.MANAGED: "optimized",
            MaturityLevel.OPTIMIZED: "optimized",
        }
        recommendations: list[dict[str, Any]] = []
        ad_hoc = [r for r in self._records if r.maturity_level == MaturityLevel.AD_HOC]
        for r in ad_hoc:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "team": r.team,
                    "domain": r.maturity_domain.value,
                    "current_level": r.maturity_level.value,
                    "target_level": level_next[r.maturity_level],
                    "priority": "high",
                    "suggestion": f"Establish repeatable processes for "
                    f"{r.maturity_domain.value} in team {r.team}",
                }
            )
        low_automation = [
            r
            for r in self._records
            if r.automated_pct < 30 and r.maturity_level != MaturityLevel.AD_HOC
        ]
        for r in low_automation:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "team": r.team,
                    "domain": r.maturity_domain.value,
                    "current_level": r.maturity_level.value,
                    "target_level": level_next[r.maturity_level],
                    "priority": "medium",
                    "suggestion": f"Increase automation ({r.automated_pct}% -> 50%+) "
                    f"for {r.maturity_domain.value}",
                }
            )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else 1,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.maturity_domain.value
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
                        "maturity_domain": r.maturity_domain.value,
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

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> OperationalMaturityReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.maturity_domain.value] = by_e1.get(r.maturity_domain.value, 0) + 1
            by_e2[r.maturity_level.value] = by_e2.get(r.maturity_level.value, 0) + 1
            by_e3[r.assessment_confidence.value] = by_e3.get(r.assessment_confidence.value, 0) + 1
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
            recs.append("Operational Maturity Engine is healthy")
        return OperationalMaturityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_maturity_domain=by_e1,
            by_maturity_level=by_e2,
            by_assessment_confidence=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("operational_maturity_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.maturity_domain.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "maturity_domain_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
