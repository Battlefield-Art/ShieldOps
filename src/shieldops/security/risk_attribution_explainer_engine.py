"""Risk Attribution Explainer Engine —
generate risk explanations, identify dominant factors,
generate triage recommendations."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ExplanationDepth(StrEnum):
    SUMMARY = "summary"
    DETAILED = "detailed"
    TECHNICAL = "technical"
    EXECUTIVE = "executive"


class AttributionFactor(StrEnum):
    TECHNIQUE_WEIGHT = "technique_weight"
    SOURCE_RELIABILITY = "source_reliability"
    TEMPORAL_RECENCY = "temporal_recency"
    ENTITY_CRITICALITY = "entity_criticality"


class ExplanationFormat(StrEnum):
    NARRATIVE = "narrative"
    STRUCTURED = "structured"
    TIMELINE = "timeline"
    GRAPH = "graph"


# --- Models ---


class RiskAttributionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""
    notable_id: str = ""
    explanation_depth: ExplanationDepth = ExplanationDepth.SUMMARY
    attribution_factor: AttributionFactor = AttributionFactor.TECHNIQUE_WEIGHT
    explanation_format: ExplanationFormat = ExplanationFormat.STRUCTURED
    risk_score: float = 0.0
    factor_contribution: float = 0.0
    explanation_text: str = ""
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskAttributionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""
    attribution_factor: AttributionFactor = AttributionFactor.TECHNIQUE_WEIGHT
    dominant_factor: str = ""
    explanation_quality: str = ""
    triage_recommendation: str = ""
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskAttributionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_risk_score: float = 0.0
    by_explanation_depth: dict[str, int] = Field(default_factory=dict)
    by_attribution_factor: dict[str, int] = Field(default_factory=dict)
    by_explanation_format: dict[str, int] = Field(default_factory=dict)
    top_attributed_entities: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class RiskAttributionExplainerEngine:
    """Generate risk explanations, identify dominant factors,
    generate triage recommendations."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[RiskAttributionRecord] = []
        self._analyses: dict[str, RiskAttributionAnalysis] = {}
        logger.info("risk_attribution_explainer_engine.init", max_records=max_records)

    def add_record(
        self,
        entity_id: str = "",
        notable_id: str = "",
        explanation_depth: ExplanationDepth = ExplanationDepth.SUMMARY,
        attribution_factor: AttributionFactor = AttributionFactor.TECHNIQUE_WEIGHT,
        explanation_format: ExplanationFormat = ExplanationFormat.STRUCTURED,
        risk_score: float = 0.0,
        factor_contribution: float = 0.0,
        explanation_text: str = "",
        description: str = "",
    ) -> RiskAttributionRecord:
        record = RiskAttributionRecord(
            entity_id=entity_id,
            notable_id=notable_id,
            explanation_depth=explanation_depth,
            attribution_factor=attribution_factor,
            explanation_format=explanation_format,
            risk_score=risk_score,
            factor_contribution=factor_contribution,
            explanation_text=explanation_text,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "risk_attribution.record_added",
            record_id=record.id,
            entity_id=entity_id,
        )
        return record

    def process(self, key: str) -> RiskAttributionAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        quality_map = {
            ExplanationDepth.TECHNICAL: "high",
            ExplanationDepth.DETAILED: "medium",
            ExplanationDepth.SUMMARY: "low",
            ExplanationDepth.EXECUTIVE: "medium",
        }
        quality = quality_map.get(rec.explanation_depth, "low")
        triage = (
            "escalate_immediately"
            if rec.risk_score >= 80
            else "investigate"
            if rec.risk_score >= 50
            else "monitor"
        )
        analysis = RiskAttributionAnalysis(
            entity_id=rec.entity_id,
            attribution_factor=rec.attribution_factor,
            dominant_factor=rec.attribution_factor.value,
            explanation_quality=quality,
            triage_recommendation=triage,
            description=f"Entity {rec.entity_id} triage={triage}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> RiskAttributionReport:
        by_ed: dict[str, int] = {}
        by_af: dict[str, int] = {}
        by_ef: dict[str, int] = {}
        scores: list[float] = []
        for r in self._records:
            by_ed[r.explanation_depth.value] = by_ed.get(r.explanation_depth.value, 0) + 1
            by_af[r.attribution_factor.value] = by_af.get(r.attribution_factor.value, 0) + 1
            by_ef[r.explanation_format.value] = by_ef.get(r.explanation_format.value, 0) + 1
            scores.append(r.risk_score)
        avg_s = round(sum(scores) / len(scores), 4) if scores else 0.0
        top = list({r.entity_id for r in self._records if r.risk_score >= 80 and r.entity_id})[:10]
        recs: list[str] = []
        if top:
            recs.append(f"{len(top)} high-risk entities need immediate triage")
        if not recs:
            recs.append("Risk attribution coverage adequate")
        return RiskAttributionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_risk_score=avg_s,
            by_explanation_depth=by_ed,
            by_attribution_factor=by_af,
            by_explanation_format=by_ef,
            top_attributed_entities=top,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        af_dist: dict[str, int] = {}
        for r in self._records:
            af_dist[r.attribution_factor.value] = af_dist.get(r.attribution_factor.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "attribution_factor_distribution": af_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("risk_attribution_explainer_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def generate_risk_explanation(
        self, entity_id: str, depth: ExplanationDepth = ExplanationDepth.SUMMARY
    ) -> dict[str, Any]:
        """Generate a risk explanation for an entity at the requested depth."""
        recs = [r for r in self._records if r.entity_id == entity_id]
        if not recs:
            return {"status": "no_data", "entity_id": entity_id}
        avg_score = round(sum(r.risk_score for r in recs) / len(recs), 4)
        factor_contributions: dict[str, float] = {}
        for r in recs:
            factor_contributions[r.attribution_factor.value] = (
                factor_contributions.get(r.attribution_factor.value, 0.0) + r.factor_contribution
            )
        ranked_factors = sorted(
            factor_contributions,
            key=lambda x: factor_contributions[x],
            reverse=True,
        )
        explanation: dict[str, Any] = {
            "entity_id": entity_id,
            "depth": depth.value,
            "avg_risk_score": avg_score,
            "record_count": len(recs),
            "top_factor": ranked_factors[0] if ranked_factors else "",
        }
        if depth in (ExplanationDepth.DETAILED, ExplanationDepth.TECHNICAL):
            explanation["factor_breakdown"] = {
                f: round(factor_contributions[f], 4) for f in ranked_factors
            }
        if depth == ExplanationDepth.TECHNICAL:
            explanation["raw_texts"] = [r.explanation_text for r in recs if r.explanation_text][:5]
        return explanation

    def identify_dominant_factors(self) -> list[dict[str, Any]]:
        """Identify dominant attribution factors across all records."""
        factor_stats: dict[str, dict[str, Any]] = {}
        for r in self._records:
            fv = r.attribution_factor.value
            if fv not in factor_stats:
                factor_stats[fv] = {
                    "factor": fv,
                    "total_contribution": 0.0,
                    "count": 0,
                    "avg_risk": 0.0,
                    "risk_sum": 0.0,
                }
            factor_stats[fv]["total_contribution"] += r.factor_contribution
            factor_stats[fv]["risk_sum"] += r.risk_score
            factor_stats[fv]["count"] += 1
        results: list[dict[str, Any]] = []
        for fv, stats in factor_stats.items():
            count = stats["count"]
            results.append(
                {
                    "factor": fv,
                    "total_contribution": round(stats["total_contribution"], 4),
                    "avg_contribution": round(stats["total_contribution"] / count, 4),
                    "avg_risk": round(stats["risk_sum"] / count, 4),
                    "record_count": count,
                }
            )
        results.sort(key=lambda x: x["total_contribution"], reverse=True)
        return results

    def generate_triage_recommendation(self, entity_id: str) -> dict[str, Any]:
        """Generate a triage recommendation for an entity based on risk signals."""
        recs = [r for r in self._records if r.entity_id == entity_id]
        if not recs:
            return {"status": "no_data", "entity_id": entity_id}
        latest = recs[-1]
        max_score = max(r.risk_score for r in recs)
        avg_score = round(sum(r.risk_score for r in recs) / len(recs), 4)
        if max_score >= 90:
            action = "escalate_immediately"
            severity = "critical"
        elif max_score >= 70:
            action = "investigate_now"
            severity = "high"
        elif max_score >= 50:
            action = "investigate_scheduled"
            severity = "medium"
        else:
            action = "monitor"
            severity = "low"
        return {
            "entity_id": entity_id,
            "recommended_action": action,
            "severity": severity,
            "max_risk_score": max_score,
            "avg_risk_score": avg_score,
            "record_count": len(recs),
            "last_format": latest.explanation_format.value,
        }
