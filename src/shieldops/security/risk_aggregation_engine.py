"""Risk Aggregation Engine — aggregate low-confidence security observations
into composite risk scores per entity using Splunk RBA methodology."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RiskSource(StrEnum):
    IDS = "ids"
    EDR = "edr"
    SIEM = "siem"
    NDR = "ndr"
    DLP = "dlp"
    UEBA = "ueba"
    CSPM = "cspm"


class AggregationStrategy(StrEnum):
    WEIGHTED_SUM = "weighted_sum"
    MAX_SCORE = "max_score"
    BAYESIAN = "bayesian"
    TEMPORAL_DECAY = "temporal_decay"


class RiskTier(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --- Models ---


class RiskAggregationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity: str = ""
    entity_type: str = ""
    risk_source: RiskSource = RiskSource.SIEM
    aggregation_strategy: AggregationStrategy = AggregationStrategy.WEIGHTED_SUM
    risk_tier: RiskTier = RiskTier.LOW
    raw_score: float = 0.0
    weighted_score: float = 0.0
    mitre_tactic: str = ""
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskAggregationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity: str = ""
    composite_score: float = 0.0
    observation_count: int = 0
    unique_tactics: int = 0
    risk_tier: RiskTier = RiskTier.LOW
    needs_action: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskAggregationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_composite_score: float = 0.0
    by_risk_source: dict[str, int] = Field(default_factory=dict)
    by_aggregation_strategy: dict[str, int] = Field(default_factory=dict)
    by_risk_tier: dict[str, int] = Field(default_factory=dict)
    critical_entities: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class RiskAggregationEngine:
    """Aggregate low-confidence security observations into composite
    risk scores per entity using Splunk RBA methodology."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[RiskAggregationRecord] = []
        self._analyses: dict[str, RiskAggregationAnalysis] = {}
        logger.info(
            "risk_aggregation_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        entity: str = "",
        entity_type: str = "",
        risk_source: RiskSource = RiskSource.SIEM,
        aggregation_strategy: AggregationStrategy = AggregationStrategy.WEIGHTED_SUM,
        risk_tier: RiskTier = RiskTier.LOW,
        raw_score: float = 0.0,
        weighted_score: float = 0.0,
        mitre_tactic: str = "",
        description: str = "",
    ) -> RiskAggregationRecord:
        record = RiskAggregationRecord(
            entity=entity,
            entity_type=entity_type,
            risk_source=risk_source,
            aggregation_strategy=aggregation_strategy,
            risk_tier=risk_tier,
            raw_score=raw_score,
            weighted_score=weighted_score,
            mitre_tactic=mitre_tactic,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "risk_aggregation_engine.record_added",
            record_id=record.id,
            entity=entity,
            risk_source=risk_source.value,
        )
        return record

    def process(self, key: str) -> RiskAggregationAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        entity_records = [r for r in self._records if r.entity == rec.entity]
        composite = round(sum(r.weighted_score for r in entity_records), 2)
        tactics = {r.mitre_tactic for r in entity_records if r.mitre_tactic}
        tier = self._score_to_tier(composite)
        analysis = RiskAggregationAnalysis(
            entity=rec.entity,
            composite_score=composite,
            observation_count=len(entity_records),
            unique_tactics=len(tactics),
            risk_tier=tier,
            needs_action=tier in (RiskTier.HIGH, RiskTier.CRITICAL),
            description=f"Entity {rec.entity} composite score {composite}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> RiskAggregationReport:
        by_rs: dict[str, int] = {}
        by_as: dict[str, int] = {}
        by_rt: dict[str, int] = {}
        scores: list[float] = []
        for r in self._records:
            by_rs[r.risk_source.value] = by_rs.get(r.risk_source.value, 0) + 1
            by_as[r.aggregation_strategy.value] = by_as.get(r.aggregation_strategy.value, 0) + 1
            by_rt[r.risk_tier.value] = by_rt.get(r.risk_tier.value, 0) + 1
            scores.append(r.weighted_score)
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        critical = list(
            {r.entity for r in self._records if r.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH)}
        )[:10]
        recs: list[str] = []
        if critical:
            recs.append(f"{len(critical)} critical/high-risk entities require review")
        if not recs:
            recs.append("Risk aggregation posture is healthy")
        return RiskAggregationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_composite_score=avg,
            by_risk_source=by_rs,
            by_aggregation_strategy=by_as,
            by_risk_tier=by_rt,
            critical_entities=critical,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        source_dist: dict[str, int] = {}
        for r in self._records:
            k = r.risk_source.value
            source_dist[k] = source_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "source_distribution": source_dist,
            "unique_entities": len({r.entity for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("risk_aggregation_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def compute_entity_risk(self, entity: str) -> dict[str, Any]:
        """Compute composite risk score for an entity using weighted sum
        of observations."""
        entity_records = [r for r in self._records if r.entity == entity]
        if not entity_records:
            return {"entity": entity, "composite_score": 0.0, "observation_count": 0}
        composite = round(sum(r.weighted_score for r in entity_records), 2)
        tactics = {r.mitre_tactic for r in entity_records if r.mitre_tactic}
        sources = {r.risk_source.value for r in entity_records}
        tier = self._score_to_tier(composite)
        return {
            "entity": entity,
            "composite_score": composite,
            "observation_count": len(entity_records),
            "unique_tactics": len(tactics),
            "unique_sources": list(sources),
            "risk_tier": tier.value,
            "needs_action": tier in (RiskTier.HIGH, RiskTier.CRITICAL),
        }

    def detect_kill_chain_progression(self) -> list[dict[str, Any]]:
        """Find entities with multiple MITRE tactics (kill chain breadth)."""
        entity_tactics: dict[str, set[str]] = {}
        entity_scores: dict[str, float] = {}
        for r in self._records:
            if r.mitre_tactic:
                entity_tactics.setdefault(r.entity, set()).add(r.mitre_tactic)
            entity_scores[r.entity] = entity_scores.get(r.entity, 0.0) + r.weighted_score
        results: list[dict[str, Any]] = []
        for entity, tactics in entity_tactics.items():
            if len(tactics) >= 2:
                results.append(
                    {
                        "entity": entity,
                        "tactic_count": len(tactics),
                        "tactics": sorted(tactics),
                        "composite_score": round(entity_scores.get(entity, 0.0), 2),
                    }
                )
        results.sort(key=lambda x: x["tactic_count"], reverse=True)
        return results

    def rank_entities_by_risk(self) -> list[dict[str, Any]]:
        """Rank all entities by composite risk score."""
        entity_scores: dict[str, float] = {}
        entity_counts: dict[str, int] = {}
        for r in self._records:
            entity_scores[r.entity] = entity_scores.get(r.entity, 0.0) + r.weighted_score
            entity_counts[r.entity] = entity_counts.get(r.entity, 0) + 1
        results: list[dict[str, Any]] = []
        for entity, score in entity_scores.items():
            results.append(
                {
                    "entity": entity,
                    "composite_score": round(score, 2),
                    "observation_count": entity_counts[entity],
                    "rank": 0,
                }
            )
        results.sort(key=lambda x: x["composite_score"], reverse=True)
        for i, entry in enumerate(results, 1):
            entry["rank"] = i
        return results

    # -- internal helpers ---

    def _score_to_tier(self, score: float) -> RiskTier:
        if score >= 90.0:
            return RiskTier.CRITICAL
        if score >= 70.0:
            return RiskTier.HIGH
        if score >= 40.0:
            return RiskTier.MEDIUM
        if score >= 10.0:
            return RiskTier.LOW
        return RiskTier.INFORMATIONAL
