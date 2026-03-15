"""Entity Risk Aggregation Engine —
compute composite risk scores per entity, detect risk concentration,
decompose risk contributors."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EntityType(StrEnum):
    USER_ACCOUNT = "user_account"
    HOST = "host"
    IP_ADDRESS = "ip_address"
    SERVICE_PRINCIPAL = "service_principal"


class AggregationMethod(StrEnum):
    WEIGHTED_SUM = "weighted_sum"
    MAX_SCORE = "max_score"
    BAYESIAN = "bayesian"
    TIME_DECAYED = "time_decayed"


class RiskTier(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# --- Models ---


class EntityRiskRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""
    entity_name: str = ""
    entity_type: EntityType = EntityType.USER_ACCOUNT
    aggregation_method: AggregationMethod = AggregationMethod.WEIGHTED_SUM
    risk_tier: RiskTier = RiskTier.LOW
    risk_score: float = 0.0
    contributor_scores: dict[str, float] = Field(default_factory=dict)
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class EntityRiskAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""
    entity_type: EntityType = EntityType.USER_ACCOUNT
    composite_score: float = 0.0
    dominant_contributor: str = ""
    risk_tier: RiskTier = RiskTier.LOW
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class EntityRiskReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_risk_score: float = 0.0
    by_entity_type: dict[str, int] = Field(default_factory=dict)
    by_aggregation_method: dict[str, int] = Field(default_factory=dict)
    by_risk_tier: dict[str, int] = Field(default_factory=dict)
    critical_entities: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class EntityRiskAggregationEngine:
    """Compute composite risk scores per entity, detect risk concentration,
    decompose risk contributors."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[EntityRiskRecord] = []
        self._analyses: dict[str, EntityRiskAnalysis] = {}
        logger.info("entity_risk_aggregation_engine.init", max_records=max_records)

    def add_record(
        self,
        entity_id: str = "",
        entity_name: str = "",
        entity_type: EntityType = EntityType.USER_ACCOUNT,
        aggregation_method: AggregationMethod = AggregationMethod.WEIGHTED_SUM,
        risk_tier: RiskTier = RiskTier.LOW,
        risk_score: float = 0.0,
        contributor_scores: dict[str, float] | None = None,
        description: str = "",
    ) -> EntityRiskRecord:
        record = EntityRiskRecord(
            entity_id=entity_id,
            entity_name=entity_name,
            entity_type=entity_type,
            aggregation_method=aggregation_method,
            risk_tier=risk_tier,
            risk_score=risk_score,
            contributor_scores=contributor_scores or {},
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "entity_risk.record_added",
            record_id=record.id,
            entity_id=entity_id,
        )
        return record

    def process(self, key: str) -> EntityRiskAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        contributors = rec.contributor_scores
        dominant = max(contributors, key=lambda x: contributors[x]) if contributors else ""
        analysis = EntityRiskAnalysis(
            entity_id=rec.entity_id,
            entity_type=rec.entity_type,
            composite_score=round(rec.risk_score, 4),
            dominant_contributor=dominant,
            risk_tier=rec.risk_tier,
            description=f"Entity {rec.entity_id} composite risk={rec.risk_score}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> EntityRiskReport:
        by_et: dict[str, int] = {}
        by_am: dict[str, int] = {}
        by_rt: dict[str, int] = {}
        scores: list[float] = []
        for r in self._records:
            by_et[r.entity_type.value] = by_et.get(r.entity_type.value, 0) + 1
            by_am[r.aggregation_method.value] = by_am.get(r.aggregation_method.value, 0) + 1
            by_rt[r.risk_tier.value] = by_rt.get(r.risk_tier.value, 0) + 1
            scores.append(r.risk_score)
        avg_s = round(sum(scores) / len(scores), 4) if scores else 0.0
        crit = list(
            {
                r.entity_id
                for r in self._records
                if r.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH)
            }
        )[:10]
        recs: list[str] = []
        if crit:
            recs.append(f"{len(crit)} entities at critical/high risk tier")
        if not recs:
            recs.append("Entity risk levels within acceptable bounds")
        return EntityRiskReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_risk_score=avg_s,
            by_entity_type=by_et,
            by_aggregation_method=by_am,
            by_risk_tier=by_rt,
            critical_entities=crit,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        et_dist: dict[str, int] = {}
        for r in self._records:
            et_dist[r.entity_type.value] = et_dist.get(r.entity_type.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "entity_type_distribution": et_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("entity_risk_aggregation_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def compute_composite_risk(self) -> list[dict[str, Any]]:
        """Compute composite risk score per entity across all records."""
        entity_records: dict[str, list[EntityRiskRecord]] = {}
        for r in self._records:
            entity_records.setdefault(r.entity_id, []).append(r)
        results: list[dict[str, Any]] = []
        for eid, recs in entity_records.items():
            method = recs[-1].aggregation_method
            raw_scores = [r.risk_score for r in recs]
            if method == AggregationMethod.MAX_SCORE:
                composite = max(raw_scores)
            elif method == AggregationMethod.TIME_DECAYED:
                total_w = 0.0
                total_s = 0.0
                now = time.time()
                for r in recs:
                    age = now - r.created_at
                    w = 1.0 / (1.0 + age / 3600)
                    total_s += r.risk_score * w
                    total_w += w
                composite = total_s / total_w if total_w else 0.0
            else:
                composite = sum(raw_scores) / len(raw_scores)
            results.append(
                {
                    "entity_id": eid,
                    "entity_type": recs[-1].entity_type.value,
                    "composite_score": round(composite, 4),
                    "aggregation_method": method.value,
                    "record_count": len(recs),
                }
            )
        results.sort(key=lambda x: x["composite_score"], reverse=True)
        return results

    def detect_risk_concentration(self, top_n: int = 5) -> list[dict[str, Any]]:
        """Detect entities that concentrate disproportionate risk."""
        entity_scores: dict[str, float] = {}
        for r in self._records:
            entity_scores[r.entity_id] = entity_scores.get(r.entity_id, 0.0) + r.risk_score
        total = sum(entity_scores.values())
        if total == 0:
            return []
        ranked = sorted(entity_scores, key=lambda x: entity_scores[x], reverse=True)
        results: list[dict[str, Any]] = []
        for eid in ranked[:top_n]:
            share = round(entity_scores[eid] / total * 100, 2)
            results.append(
                {
                    "entity_id": eid,
                    "total_risk_score": round(entity_scores[eid], 4),
                    "share_pct": share,
                    "concentrated": share > (100 / max(len(entity_scores), 1) * 2),
                }
            )
        return results

    def decompose_risk_contributors(self, entity_id: str) -> dict[str, Any]:
        """Decompose risk contributors for a given entity."""
        recs = [r for r in self._records if r.entity_id == entity_id]
        if not recs:
            return {"status": "no_data", "entity_id": entity_id}
        contrib_totals: dict[str, float] = {}
        for r in recs:
            for contributor, score in r.contributor_scores.items():
                contrib_totals[contributor] = contrib_totals.get(contributor, 0.0) + score
        total_contrib = sum(contrib_totals.values())
        breakdown: list[dict[str, Any]] = []
        for contributor, score in contrib_totals.items():
            share = round(score / total_contrib * 100, 2) if total_contrib else 0.0
            breakdown.append(
                {
                    "contributor": contributor,
                    "total_score": round(score, 4),
                    "share_pct": share,
                }
            )
        breakdown.sort(key=lambda x: x["total_score"], reverse=True)
        return {
            "entity_id": entity_id,
            "record_count": len(recs),
            "total_contributor_score": round(total_contrib, 4),
            "contributors": breakdown,
        }
