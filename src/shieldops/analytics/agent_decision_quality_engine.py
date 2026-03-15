"""AgentDecisionQualityEngine — Evaluate the quality of agent decisions over time."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DecisionType(StrEnum):
    INVESTIGATE = "investigate"
    REMEDIATE = "remediate"
    ESCALATE = "escalate"
    IGNORE = "ignore"


class DecisionOutcome(StrEnum):
    CORRECT = "correct"
    INCORRECT = "incorrect"
    PARTIAL = "partial"
    OVERRIDDEN = "overridden"


class QualityTrend(StrEnum):
    IMPROVING = "improving"
    STABLE = "stable"
    DECLINING = "declining"


# --- Models ---


class AgentDecisionQualityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    decision_type: DecisionType = DecisionType.INVESTIGATE
    decision_outcome: DecisionOutcome = DecisionOutcome.CORRECT
    quality_trend: QualityTrend = QualityTrend.STABLE
    score: float = 0.0
    confidence: float = 0.0
    response_time_sec: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentDecisionQualityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    decision_type: DecisionType = DecisionType.INVESTIGATE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentDecisionQualityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_decision_type: dict[str, int] = Field(default_factory=dict)
    by_decision_outcome: dict[str, int] = Field(default_factory=dict)
    by_quality_trend: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentDecisionQualityEngine:
    """Evaluate the quality of agent decisions over time."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AgentDecisionQualityRecord] = []
        self._analyses: list[AgentDecisionQualityAnalysis] = []
        logger.info(
            "agent_decision_quality_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        decision_type: DecisionType = DecisionType.INVESTIGATE,
        decision_outcome: DecisionOutcome = DecisionOutcome.CORRECT,
        quality_trend: QualityTrend = QualityTrend.STABLE,
        score: float = 0.0,
        confidence: float = 0.0,
        response_time_sec: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> AgentDecisionQualityRecord:
        record = AgentDecisionQualityRecord(
            name=name,
            decision_type=decision_type,
            decision_outcome=decision_outcome,
            quality_trend=quality_trend,
            score=score,
            confidence=confidence,
            response_time_sec=response_time_sec,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_decision_quality_engine.record_added",
            record_id=record.id,
            name=name,
            decision_type=decision_type.value,
            decision_outcome=decision_outcome.value,
        )
        return record

    def get_record(self, record_id: str) -> AgentDecisionQualityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        decision_type: DecisionType | None = None,
        decision_outcome: DecisionOutcome | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AgentDecisionQualityRecord]:
        results = list(self._records)
        if decision_type is not None:
            results = [r for r in results if r.decision_type == decision_type]
        if decision_outcome is not None:
            results = [r for r in results if r.decision_outcome == decision_outcome]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        decision_type: DecisionType = DecisionType.INVESTIGATE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AgentDecisionQualityAnalysis:
        analysis = AgentDecisionQualityAnalysis(
            name=name,
            decision_type=decision_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "agent_decision_quality_engine.analysis_added",
            name=name,
            decision_type=decision_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_decision_accuracy(self) -> list[dict[str, Any]]:
        """Compute decision accuracy rates by type and agent."""
        type_outcomes: dict[str, dict[str, int]] = {}
        for r in self._records:
            dt = r.decision_type.value
            type_outcomes.setdefault(dt, {"total": 0, "correct": 0, "partial": 0})
            type_outcomes[dt]["total"] += 1
            if r.decision_outcome == DecisionOutcome.CORRECT:
                type_outcomes[dt]["correct"] += 1
            elif r.decision_outcome == DecisionOutcome.PARTIAL:
                type_outcomes[dt]["partial"] += 1
        results: list[dict[str, Any]] = []
        for dt, counts in type_outcomes.items():
            accuracy = round(counts["correct"] / counts["total"] * 100, 2) if counts["total"] else 0
            results.append(
                {
                    "decision_type": dt,
                    "total_decisions": counts["total"],
                    "correct": counts["correct"],
                    "partial": counts["partial"],
                    "accuracy_pct": accuracy,
                }
            )
        return sorted(results, key=lambda x: x["accuracy_pct"])

    def identify_systematic_errors(self) -> list[dict[str, Any]]:
        """Identify patterns in incorrect decisions."""
        svc_errors: dict[str, list[AgentDecisionQualityRecord]] = {}
        for r in self._records:
            if r.decision_outcome in (DecisionOutcome.INCORRECT, DecisionOutcome.OVERRIDDEN):
                svc_errors.setdefault(r.service, []).append(r)
        patterns: list[dict[str, Any]] = []
        for svc, errors in svc_errors.items():
            type_counts: dict[str, int] = {}
            for e in errors:
                type_counts[e.decision_type.value] = type_counts.get(e.decision_type.value, 0) + 1
            patterns.append(
                {
                    "service": svc,
                    "error_count": len(errors),
                    "error_by_type": type_counts,
                    "avg_confidence": round(sum(e.confidence for e in errors) / len(errors), 2),
                    "is_systematic": len(errors) >= 3,
                }
            )
        return sorted(patterns, key=lambda x: x["error_count"], reverse=True)

    def recommend_decision_improvements(self) -> list[dict[str, Any]]:
        """Recommend improvements to decision quality."""
        recommendations: list[dict[str, Any]] = []
        incorrect = [r for r in self._records if r.decision_outcome == DecisionOutcome.INCORRECT]
        for r in incorrect:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "decision_type": r.decision_type.value,
                    "issue": "incorrect_decision",
                    "priority": "high",
                    "suggestion": f"Review {r.decision_type.value} decision for {r.service} "
                    f"(confidence: {r.confidence})",
                }
            )
        low_confidence = [
            r
            for r in self._records
            if r.confidence < 0.5 and r.decision_outcome != DecisionOutcome.INCORRECT
        ]
        for r in low_confidence:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "decision_type": r.decision_type.value,
                    "issue": "low_confidence",
                    "priority": "medium",
                    "suggestion": f"Improve training data for {r.decision_type.value} decisions",
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
            key = r.decision_type.value
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
                        "decision_type": r.decision_type.value,
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

    def generate_report(self) -> AgentDecisionQualityReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.decision_type.value] = by_e1.get(r.decision_type.value, 0) + 1
            by_e2[r.decision_outcome.value] = by_e2.get(r.decision_outcome.value, 0) + 1
            by_e3[r.quality_trend.value] = by_e3.get(r.quality_trend.value, 0) + 1
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
            recs.append("Agent Decision Quality Engine is healthy")
        return AgentDecisionQualityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_decision_type=by_e1,
            by_decision_outcome=by_e2,
            by_quality_trend=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_decision_quality_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.decision_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "decision_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
