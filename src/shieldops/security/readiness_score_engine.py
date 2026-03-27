"""ReadinessScoreEngine -- score attack readiness."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AssessmentDomain(StrEnum):
    PREVENTION = "prevention"
    DETECTION = "detection"
    RESPONSE = "response"
    RECOVERY = "recovery"
    GOVERNANCE = "governance"


class ReadinessMetric(StrEnum):
    MTTD = "mttd"
    MTTR = "mttr"
    COVERAGE = "coverage"
    DEPTH = "depth"
    AUTOMATION = "automation"


class ScenarioComplexity(StrEnum):
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    APT = "apt"


# --- Models ---


class ReadinessScoreRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    domain: AssessmentDomain = AssessmentDomain.DETECTION
    metric: ReadinessMetric = ReadinessMetric.COVERAGE
    complexity: ScenarioComplexity = ScenarioComplexity.BASIC
    score: float = 0.0
    scenario: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ReadinessScoreAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    domain: AssessmentDomain = AssessmentDomain.DETECTION
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ReadinessScoreReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_domain: dict[str, int] = Field(default_factory=dict)
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_complexity: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ReadinessScoreEngine:
    """Score attack readiness across domains."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ReadinessScoreRecord] = []
        self._analyses: list[ReadinessScoreAnalysis] = []
        logger.info(
            "readiness_score_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def add_record(
        self,
        name: str,
        domain: AssessmentDomain = AssessmentDomain.DETECTION,
        metric: ReadinessMetric = ReadinessMetric.COVERAGE,
        complexity: ScenarioComplexity = ScenarioComplexity.BASIC,
        score: float = 0.0,
        scenario: str = "",
        service: str = "",
        team: str = "",
    ) -> ReadinessScoreRecord:
        record = ReadinessScoreRecord(
            name=name,
            domain=domain,
            metric=metric,
            complexity=complexity,
            score=score,
            scenario=scenario,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "readiness_score_engine.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> ReadinessScoreRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        domain: AssessmentDomain | None = None,
        complexity: ScenarioComplexity | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ReadinessScoreRecord]:
        results = list(self._records)
        if domain is not None:
            results = [r for r in results if r.domain == domain]
        if complexity is not None:
            results = [r for r in results if r.complexity == complexity]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        domain: AssessmentDomain = AssessmentDomain.DETECTION,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ReadinessScoreAnalysis:
        analysis = ReadinessScoreAnalysis(
            name=name,
            domain=domain,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ---

    def score_readiness(
        self,
    ) -> list[dict[str, Any]]:
        """Score readiness per domain."""
        domain_data: dict[str, list[ReadinessScoreRecord]] = {}
        for r in self._records:
            domain_data.setdefault(r.domain.value, []).append(r)
        results: list[dict[str, Any]] = []
        for domain, records in domain_data.items():
            scores = [r.score for r in records]
            avg = round(sum(scores) / len(scores), 2)
            results.append(
                {
                    "domain": domain,
                    "avg_score": avg,
                    "count": len(records),
                    "ready": avg >= self._threshold,
                }
            )
        return sorted(results, key=lambda x: x["avg_score"])

    def compare_scenarios(
        self,
    ) -> list[dict[str, Any]]:
        """Compare readiness across scenarios."""
        scenario_data: dict[str, list[ReadinessScoreRecord]] = {}
        for r in self._records:
            scenario_data.setdefault(r.scenario, []).append(r)
        results: list[dict[str, Any]] = []
        for scenario, records in scenario_data.items():
            scores = [r.score for r in records]
            avg = round(sum(scores) / len(scores), 2)
            results.append(
                {
                    "scenario": scenario,
                    "avg_score": avg,
                    "count": len(records),
                    "complexity": records[-1].complexity.value,
                }
            )
        return sorted(results, key=lambda x: x["avg_score"])

    def track_improvement(
        self,
    ) -> dict[str, Any]:
        """Track improvement over time."""
        if len(self._records) < 2:
            return {
                "improvement": 0.0,
                "samples": len(self._records),
            }
        half = len(self._records) // 2
        first_half = self._records[:half]
        second_half = self._records[half:]
        avg_first = sum(r.score for r in first_half) / len(first_half)
        avg_second = sum(r.score for r in second_half) / len(second_half)
        return {
            "early_avg": round(avg_first, 2),
            "recent_avg": round(avg_second, 2),
            "improvement": round(avg_second - avg_first, 2),
            "samples": len(self._records),
        }

    # -- standard methods ---

    def identify_gaps(
        self,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "domain": r.domain.value,
                        "score": r.score,
                        "service": r.service,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.scenario == key]
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
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    def generate_report(
        self,
    ) -> ReadinessScoreReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            v1 = r.domain.value
            by_e1[v1] = by_e1.get(v1, 0) + 1
            v2 = r.metric.value
            by_e2[v2] = by_e2.get(v2, 0) + 1
            v3 = r.complexity.value
            by_e3[v3] = by_e3.get(v3, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Readiness Score Engine healthy")
        return ReadinessScoreReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_domain=by_e1,
            by_metric=by_e2,
            by_complexity=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("readiness_score_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.domain.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "domain_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
