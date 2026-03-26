"""Action Recommendation Engine — recommend response actions."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ActionCategory(StrEnum):
    CONTAIN = "contain"
    INVESTIGATE = "investigate"
    REMEDIATE = "remediate"
    MONITOR = "monitor"
    ESCALATE = "escalate"


class RecommendationBasis(StrEnum):
    PATTERN_MATCH = "pattern_match"
    LLM_REASONING = "llm_reasoning"
    HISTORICAL = "historical"
    POLICY = "policy"


class EffectivenessScore(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


# --- Models ---


class RecommendationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    situation_id: str = ""
    category: ActionCategory = ActionCategory.INVESTIGATE
    basis: RecommendationBasis = RecommendationBasis.PATTERN_MATCH
    effectiveness: EffectivenessScore = EffectivenessScore.UNKNOWN
    action_description: str = ""
    confidence: float = 0.0
    accepted: bool | None = None
    outcome_feedback: str = ""
    created_at: float = Field(default_factory=time.time)


class RecommendationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    category: str = ""
    total_recommendations: int = 0
    acceptance_rate: float = 0.0
    avg_confidence: float = 0.0
    effectiveness_dist: dict[str, int] = Field(default_factory=dict)
    analyzed_at: float = Field(default_factory=time.time)


class RecommendationReport(BaseModel):
    total_recommendations: int = 0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_basis: dict[str, int] = Field(default_factory=dict)
    by_effectiveness: dict[str, int] = Field(default_factory=dict)
    acceptance_rate_pct: float = 0.0
    avg_confidence: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ActionRecommendationEngine:
    """Generate and track action recommendations."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[RecommendationRecord] = []
        logger.info(
            "action_recommendation.initialized",
            max_records=max_records,
        )

    # -- record / query --

    def add_record(
        self,
        situation_id: str = "",
        category: ActionCategory = (ActionCategory.INVESTIGATE),
        basis: RecommendationBasis = (RecommendationBasis.PATTERN_MATCH),
        action_description: str = "",
        confidence: float = 0.5,
    ) -> RecommendationRecord:
        record = RecommendationRecord(
            situation_id=situation_id,
            category=category,
            basis=basis,
            action_description=action_description,
            confidence=confidence,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "action_recommendation.record_added",
            record_id=record.id,
            category=category.value,
            confidence=confidence,
        )
        return record

    def process(self, category: str) -> RecommendationAnalysis:
        items = [r for r in self._records if r.category.value == category]
        if not items:
            return RecommendationAnalysis(category=category)
        decided = [r for r in items if r.accepted is not None]
        accepted = sum(1 for r in decided if r.accepted)
        acc_rate = round(accepted / len(decided) * 100, 2) if decided else 0.0
        avg_conf = round(
            sum(r.confidence for r in items) / len(items),
            4,
        )
        eff_dist: dict[str, int] = {}
        for r in items:
            key = r.effectiveness.value
            eff_dist[key] = eff_dist.get(key, 0) + 1
        return RecommendationAnalysis(
            category=category,
            total_recommendations=len(items),
            acceptance_rate=acc_rate,
            avg_confidence=avg_conf,
            effectiveness_dist=eff_dist,
        )

    def generate_report(
        self,
    ) -> RecommendationReport:
        by_cat: dict[str, int] = {}
        by_basis: dict[str, int] = {}
        by_eff: dict[str, int] = {}
        for r in self._records:
            by_cat[r.category.value] = by_cat.get(r.category.value, 0) + 1
            by_basis[r.basis.value] = by_basis.get(r.basis.value, 0) + 1
            by_eff[r.effectiveness.value] = by_eff.get(r.effectiveness.value, 0) + 1
        total = len(self._records)
        decided = [r for r in self._records if r.accepted is not None]
        accepted = sum(1 for r in decided if r.accepted)
        acc_rate = round(accepted / len(decided) * 100, 2) if decided else 0.0
        avg_conf = (
            round(
                sum(r.confidence for r in self._records) / total,
                4,
            )
            if total
            else 0.0
        )
        recs: list[str] = []
        if acc_rate < 50 and len(decided) > 5:
            recs.append("Low acceptance rate — review recommendation quality")
        low_ct = by_eff.get(EffectivenessScore.LOW.value, 0)
        if low_ct > 0:
            recs.append(f"{low_ct} low-effectiveness action(s) — retrain models")
        if avg_conf < 0.5 and total > 0:
            recs.append("Low average confidence — improve signal quality")
        if not recs:
            recs.append("Recommendation quality is healthy")
        return RecommendationReport(
            total_recommendations=total,
            by_category=by_cat,
            by_basis=by_basis,
            by_effectiveness=by_eff,
            acceptance_rate_pct=acc_rate,
            avg_confidence=avg_conf,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        cat_dist: dict[str, int] = {}
        for r in self._records:
            key = r.category.value
            cat_dist[key] = cat_dist.get(key, 0) + 1
        decided = [r for r in self._records if r.accepted is not None]
        return {
            "total_recommendations": len(self._records),
            "max_records": self._max_records,
            "category_distribution": cat_dist,
            "decided_count": len(decided),
            "accepted_count": sum(1 for r in decided if r.accepted),
            "unique_situations": len({r.situation_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("action_recommendation.cleared")
        return {"status": "cleared"}

    # -- domain operations --

    def generate_recommendation(
        self,
        situation_id: str,
        category: ActionCategory = (ActionCategory.INVESTIGATE),
        basis: RecommendationBasis = (RecommendationBasis.PATTERN_MATCH),
        action_description: str = "",
        confidence: float = 0.5,
    ) -> dict[str, Any]:
        """Generate an action recommendation."""
        record = self.add_record(
            situation_id=situation_id,
            category=category,
            basis=basis,
            action_description=action_description,
            confidence=confidence,
        )
        return {
            "record_id": record.id,
            "situation_id": situation_id,
            "category": category.value,
            "basis": basis.value,
            "action": action_description,
            "confidence": confidence,
            "generated": True,
        }

    def track_acceptance_rate(
        self,
        category: ActionCategory | None = None,
        window_size: int = 50,
    ) -> dict[str, Any]:
        """Track acceptance rate for actions."""
        targets = self._records
        if category:
            targets = [r for r in targets if r.category == category]
        recent = targets[-window_size:]
        decided = [r for r in recent if r.accepted is not None]
        if not decided:
            return {
                "category": (category.value if category else "all"),
                "decided_count": 0,
                "acceptance_rate_pct": 0.0,
            }
        accepted = sum(1 for r in decided if r.accepted)
        rate = round(accepted / len(decided) * 100, 2)
        return {
            "category": (category.value if category else "all"),
            "window_size": window_size,
            "decided_count": len(decided),
            "accepted_count": accepted,
            "acceptance_rate_pct": rate,
        }

    def learn_from_outcomes(
        self,
        record_id: str,
        accepted: bool,
        effectiveness: EffectivenessScore = (EffectivenessScore.UNKNOWN),
        outcome_feedback: str = "",
    ) -> dict[str, Any]:
        """Record outcome feedback for learning."""
        record = None
        for r in self._records:
            if r.id == record_id:
                record = r
                break
        if record is None:
            return {
                "found": False,
                "record_id": record_id,
            }
        record.accepted = accepted
        record.effectiveness = effectiveness
        record.outcome_feedback = outcome_feedback
        logger.info(
            "action_recommendation.outcome_learned",
            record_id=record_id,
            accepted=accepted,
            effectiveness=effectiveness.value,
        )
        return {
            "found": True,
            "record_id": record_id,
            "accepted": accepted,
            "effectiveness": effectiveness.value,
            "feedback": outcome_feedback,
            "learned": True,
        }
