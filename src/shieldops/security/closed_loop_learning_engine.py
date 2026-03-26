"""Closed Loop Learning Engine — feedback from resolved incidents."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class FeedbackType(StrEnum):
    ANALYST_REVIEW = "analyst_review"
    AUTOMATED_VALIDATION = "automated_validation"
    FALSE_POSITIVE_REPORT = "false_positive_report"
    ESCALATION_FEEDBACK = "escalation_feedback"
    OUTCOME_ASSESSMENT = "outcome_assessment"


class LearningOutcome(StrEnum):
    IMPROVED = "improved"
    DEGRADED = "degraded"
    UNCHANGED = "unchanged"
    NEEDS_DATA = "needs_data"
    RETRAINED = "retrained"


class ConfidenceAdjustment(StrEnum):
    INCREASE = "increase"
    DECREASE = "decrease"
    MAINTAIN = "maintain"
    RESET = "reset"
    CALIBRATE = "calibrate"


# --- Models ---


class FeedbackRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    feedback_type: FeedbackType = FeedbackType.ANALYST_REVIEW
    learning_outcome: LearningOutcome = LearningOutcome.UNCHANGED
    confidence_adj: ConfidenceAdjustment = ConfidenceAdjustment.MAINTAIN
    original_confidence: float = 0.0
    adjusted_confidence: float = 0.0
    rule_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class FeedbackAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    feedback_type: FeedbackType = FeedbackType.ANALYST_REVIEW
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class FeedbackReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_confidence_delta: float = 0.0
    improvement_rate: float = 0.0
    by_feedback_type: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    by_adjustment: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ClosedLoopLearningEngine:
    """Capture feedback to improve triage quality."""

    def __init__(
        self,
        max_records: int = 200000,
        improvement_threshold: float = 60.0,
    ) -> None:
        self._max_records = max_records
        self._improvement_threshold = improvement_threshold
        self._records: list[FeedbackRecord] = []
        self._analyses: list[FeedbackAnalysis] = []
        logger.info(
            "closed_loop_learning_engine.init",
            max_records=max_records,
        )

    # -- record --

    def add_record(
        self,
        incident_id: str = "",
        feedback_type: FeedbackType = (FeedbackType.ANALYST_REVIEW),
        learning_outcome: LearningOutcome = (LearningOutcome.UNCHANGED),
        confidence_adj: ConfidenceAdjustment = (ConfidenceAdjustment.MAINTAIN),
        original_confidence: float = 0.0,
        adjusted_confidence: float = 0.0,
        rule_id: str = "",
        service: str = "",
        team: str = "",
    ) -> FeedbackRecord:
        record = FeedbackRecord(
            incident_id=incident_id,
            feedback_type=feedback_type,
            learning_outcome=learning_outcome,
            confidence_adj=confidence_adj,
            original_confidence=original_confidence,
            adjusted_confidence=adjusted_confidence,
            rule_id=rule_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "closed_loop_learning.record_added",
            record_id=record.id,
        )
        return record

    # -- process --

    def process(self, incident_id: str) -> FeedbackAnalysis:
        relevant = [r for r in self._records if r.incident_id == incident_id]
        if not relevant:
            analysis = FeedbackAnalysis(
                incident_id=incident_id,
                description="no records found",
            )
            self._analyses.append(analysis)
            return analysis
        improved = sum(1 for r in relevant if r.learning_outcome == LearningOutcome.IMPROVED)
        rate = (improved / len(relevant)) * 100
        breached = rate < self._improvement_threshold
        analysis = FeedbackAnalysis(
            incident_id=incident_id,
            analysis_score=round(rate, 2),
            threshold=self._improvement_threshold,
            breached=breached,
            description=(f"improvement_rate={round(rate, 2)}%"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain methods --

    def apply_feedback(
        self,
    ) -> dict[str, Any]:
        """Summarize feedback applications by type."""
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.feedback_type.value
            delta = r.adjusted_confidence - r.original_confidence
            type_data.setdefault(key, []).append(delta)
        result: dict[str, Any] = {}
        for ft, deltas in type_data.items():
            result[ft] = {
                "count": len(deltas),
                "avg_delta": round(sum(deltas) / len(deltas), 4),
            }
        return result

    def recalibrate_confidence(
        self,
    ) -> list[dict[str, Any]]:
        """Identify rules needing recalibration."""
        rule_data: dict[str, list[float]] = {}
        for r in self._records:
            if r.rule_id:
                delta = r.adjusted_confidence - r.original_confidence
                rule_data.setdefault(r.rule_id, []).append(delta)
        results: list[dict[str, Any]] = []
        for rule_id, deltas in rule_data.items():
            avg_d = sum(deltas) / len(deltas)
            if abs(avg_d) > 0.1:
                results.append(
                    {
                        "rule_id": rule_id,
                        "avg_delta": round(avg_d, 4),
                        "samples": len(deltas),
                        "action": ("increase" if avg_d > 0 else "decrease"),
                    }
                )
        return sorted(
            results,
            key=lambda x: abs(x["avg_delta"]),
            reverse=True,
        )

    def measure_improvement(
        self,
    ) -> dict[str, Any]:
        """Split-half improvement measurement."""
        if len(self._records) < 2:
            return {
                "trend": "insufficient_data",
                "delta": 0.0,
            }
        mid = len(self._records) // 2
        first = self._records[:mid]
        second = self._records[mid:]
        first_improved = sum(1 for r in first if r.learning_outcome == LearningOutcome.IMPROVED)
        second_improved = sum(1 for r in second if r.learning_outcome == LearningOutcome.IMPROVED)
        r1 = first_improved / len(first) * 100 if first else 0.0
        r2 = second_improved / len(second) * 100 if second else 0.0
        delta = round(r2 - r1, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "first_half_rate": round(r1, 2),
            "second_half_rate": round(r2, 2),
        }

    # -- report / stats --

    def generate_report(self) -> FeedbackReport:
        by_ft: dict[str, int] = {}
        by_out: dict[str, int] = {}
        by_adj: dict[str, int] = {}
        for r in self._records:
            by_ft[r.feedback_type.value] = by_ft.get(r.feedback_type.value, 0) + 1
            by_out[r.learning_outcome.value] = by_out.get(r.learning_outcome.value, 0) + 1
            by_adj[r.confidence_adj.value] = by_adj.get(r.confidence_adj.value, 0) + 1
        deltas = [r.adjusted_confidence - r.original_confidence for r in self._records]
        avg_delta = round(sum(deltas) / len(deltas), 4) if deltas else 0.0
        improved = sum(1 for r in self._records if r.learning_outcome == LearningOutcome.IMPROVED)
        imp_rate = (
            round(
                improved / len(self._records) * 100,
                2,
            )
            if self._records
            else 0.0
        )
        recs: list[str] = []
        if imp_rate < self._improvement_threshold:
            recs.append(f"Improvement rate {imp_rate}% below {self._improvement_threshold}%")
        if not recs:
            recs.append("Closed-loop learning is healthy")
        return FeedbackReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_confidence_delta=avg_delta,
            improvement_rate=imp_rate,
            by_feedback_type=by_ft,
            by_outcome=by_out,
            by_adjustment=by_adj,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "improvement_threshold": (self._improvement_threshold),
            "unique_rules": len({r.rule_id for r in self._records if r.rule_id}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("closed_loop_learning_engine.cleared")
        return {"status": "cleared"}
