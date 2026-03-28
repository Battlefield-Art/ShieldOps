"""RiskScoringEngineV2 — composite risk scoring."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ScoreFactor(StrEnum):
    EXPLOITABILITY = "exploitability"
    BLAST_RADIUS = "blast_radius"
    ASSET_VALUE = "asset_value"
    DATA_SENSITIVITY = "data_sensitivity"


class WeightProfile(StrEnum):
    DEFAULT = "default"
    COMPLIANCE_HEAVY = "compliance_heavy"
    SECURITY_HEAVY = "security_heavy"
    BALANCED = "balanced"


class ScoreMethod(StrEnum):
    WEIGHTED_SUM = "weighted_sum"
    MAX_FACTOR = "max_factor"
    GEOMETRIC_MEAN = "geometric_mean"


# --- Models ---


class RiskScoringRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    score_factor: ScoreFactor = ScoreFactor.EXPLOITABILITY
    weight_profile: WeightProfile = WeightProfile.DEFAULT
    score_method: ScoreMethod = ScoreMethod.WEIGHTED_SUM
    score: float = 0.0
    raw_scores: dict[str, float] = Field(default_factory=dict)
    business_context: str = ""
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskScoringAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    score_factor: ScoreFactor = ScoreFactor.EXPLOITABILITY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskScoringReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_score_factor: dict[str, int] = Field(default_factory=dict)
    by_weight_profile: dict[str, int] = Field(default_factory=dict)
    by_score_method: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class RiskScoringEngineV2:
    """Composite risk scoring with profiles."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[RiskScoringRecord] = []
        self._analyses: list[RiskScoringAnalysis] = []
        logger.info(
            "risk_scoring_engine_v2.init",
            max_records=max_records,
        )

    def add_record(
        self,
        name: str,
        score_factor: ScoreFactor = (ScoreFactor.EXPLOITABILITY),
        weight_profile: WeightProfile = (WeightProfile.DEFAULT),
        score_method: ScoreMethod = (ScoreMethod.WEIGHTED_SUM),
        score: float = 0.0,
        raw_scores: dict[str, float] | None = None,
        business_context: str = "",
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> RiskScoringRecord:
        record = RiskScoringRecord(
            name=name,
            score_factor=score_factor,
            weight_profile=weight_profile,
            score_method=score_method,
            score=score,
            raw_scores=raw_scores or {},
            business_context=business_context,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "risk_scoring_v2.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> RiskScoringRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        score_factor: ScoreFactor | None = None,
        weight_profile: WeightProfile | None = None,
        limit: int = 50,
    ) -> list[RiskScoringRecord]:
        results = list(self._records)
        if score_factor is not None:
            results = [r for r in results if r.score_factor == score_factor]
        if weight_profile is not None:
            results = [r for r in results if r.weight_profile == weight_profile]
        return results[-limit:]

    # -- domain methods ---

    def calculate_composite_risk(
        self,
    ) -> list[dict[str, Any]]:
        """Calculate composite risk per entity."""
        entity_data: dict[str, list[RiskScoringRecord]] = {}
        for r in self._records:
            entity_data.setdefault(r.entity or r.name, []).append(r)
        results: list[dict[str, Any]] = []
        for entity, recs in entity_data.items():
            scores = [r.score for r in recs]
            composite = round(sum(scores) / len(scores), 2)
            results.append(
                {
                    "entity": entity,
                    "composite_risk": composite,
                    "factor_count": len(recs),
                    "max_score": max(scores),
                    "min_score": min(scores),
                }
            )
        return sorted(
            results,
            key=lambda x: x["composite_risk"],
            reverse=True,
        )

    def apply_business_context(
        self,
    ) -> list[dict[str, Any]]:
        """Apply business context adjustments."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            modifier = 1.0
            ctx = r.business_context.lower()
            if "critical" in ctx:
                modifier = 1.5
            elif "important" in ctx:
                modifier = 1.2
            adjusted = round(r.score * modifier, 2)
            results.append(
                {
                    "name": r.name,
                    "original": r.score,
                    "adjusted": adjusted,
                    "context": r.business_context,
                    "modifier": modifier,
                }
            )
        return sorted(
            results,
            key=lambda x: x["adjusted"],
            reverse=True,
        )

    def rank_by_urgency(
        self,
    ) -> list[dict[str, Any]]:
        """Rank findings by urgency."""
        results: list[dict[str, Any]] = []
        for i, r in enumerate(
            sorted(
                self._records,
                key=lambda x: x.score,
                reverse=True,
            )
        ):
            urgency = "low"
            if r.score >= 90:
                urgency = "immediate"
            elif r.score >= 70:
                urgency = "urgent"
            elif r.score >= 50:
                urgency = "scheduled"
            results.append(
                {
                    "rank": i + 1,
                    "name": r.name,
                    "score": r.score,
                    "urgency": urgency,
                    "service": r.service,
                }
            )
        return results

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

    def generate_report(self) -> RiskScoringReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.score_factor.value] = by_e1.get(r.score_factor.value, 0) + 1
            by_e2[r.weight_profile.value] = by_e2.get(r.weight_profile.value, 0) + 1
            by_e3[r.score_method.value] = by_e3.get(r.score_method.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gaps = [r.name for r in self._records if r.score < self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Risk scoring is healthy")
        return RiskScoringReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_score_factor=by_e1,
            by_weight_profile=by_e2,
            by_score_method=by_e3,
            top_gaps=gaps,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.score_factor.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "factor_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("risk_scoring_engine_v2.cleared")
        return {"status": "cleared"}
