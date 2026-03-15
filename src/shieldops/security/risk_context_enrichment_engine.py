"""Risk Context Enrichment Engine —
enrich risk with contextual signals, detect missing context,
evaluate context freshness."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ContextType(StrEnum):
    ASSET_CRITICALITY = "asset_criticality"
    BUSINESS_UNIT = "business_unit"
    USER_ROLE = "user_role"
    DATA_CLASSIFICATION = "data_classification"


class EnrichmentSource(StrEnum):
    CMDB = "cmdb"
    IAM_DIRECTORY = "iam_directory"
    THREAT_INTEL = "threat_intel"
    BUSINESS_REGISTRY = "business_registry"


class ContextImpact(StrEnum):
    AMPLIFYING = "amplifying"
    NEUTRAL = "neutral"
    MITIGATING = "mitigating"
    OVERRIDING = "overriding"


# --- Models ---


class RiskContextRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""
    context_type: ContextType = ContextType.ASSET_CRITICALITY
    enrichment_source: EnrichmentSource = EnrichmentSource.CMDB
    context_impact: ContextImpact = ContextImpact.NEUTRAL
    base_risk_score: float = 0.0
    enriched_risk_score: float = 0.0
    context_value: str = ""
    context_age_hours: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskContextAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_id: str = ""
    context_type: ContextType = ContextType.ASSET_CRITICALITY
    enrichment_delta: float = 0.0
    context_stale: bool = False
    missing_context_types: list[str] = Field(default_factory=list)
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskContextReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_enriched_risk: float = 0.0
    by_context_type: dict[str, int] = Field(default_factory=dict)
    by_enrichment_source: dict[str, int] = Field(default_factory=dict)
    by_context_impact: dict[str, int] = Field(default_factory=dict)
    stale_context_entity_ids: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class RiskContextEnrichmentEngine:
    """Enrich risk with contextual signals, detect missing context,
    evaluate context freshness."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[RiskContextRecord] = []
        self._analyses: dict[str, RiskContextAnalysis] = {}
        logger.info("risk_context_enrichment_engine.init", max_records=max_records)

    def add_record(
        self,
        entity_id: str = "",
        context_type: ContextType = ContextType.ASSET_CRITICALITY,
        enrichment_source: EnrichmentSource = EnrichmentSource.CMDB,
        context_impact: ContextImpact = ContextImpact.NEUTRAL,
        base_risk_score: float = 0.0,
        enriched_risk_score: float = 0.0,
        context_value: str = "",
        context_age_hours: float = 0.0,
        description: str = "",
    ) -> RiskContextRecord:
        record = RiskContextRecord(
            entity_id=entity_id,
            context_type=context_type,
            enrichment_source=enrichment_source,
            context_impact=context_impact,
            base_risk_score=base_risk_score,
            enriched_risk_score=enriched_risk_score,
            context_value=context_value,
            context_age_hours=context_age_hours,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "risk_context.record_added",
            record_id=record.id,
            entity_id=entity_id,
        )
        return record

    def process(self, key: str) -> RiskContextAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        delta = round(rec.enriched_risk_score - rec.base_risk_score, 4)
        stale = rec.context_age_hours > 168  # older than 7 days
        all_types = {ct.value for ct in ContextType}
        entity_types = {r.context_type.value for r in self._records if r.entity_id == rec.entity_id}
        missing = list(all_types - entity_types)
        analysis = RiskContextAnalysis(
            entity_id=rec.entity_id,
            context_type=rec.context_type,
            enrichment_delta=delta,
            context_stale=stale,
            missing_context_types=missing,
            description=f"Entity {rec.entity_id} enrichment delta={delta}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> RiskContextReport:
        by_ct: dict[str, int] = {}
        by_es: dict[str, int] = {}
        by_ci: dict[str, int] = {}
        risks: list[float] = []
        stale_ids: list[str] = []
        for r in self._records:
            by_ct[r.context_type.value] = by_ct.get(r.context_type.value, 0) + 1
            by_es[r.enrichment_source.value] = by_es.get(r.enrichment_source.value, 0) + 1
            by_ci[r.context_impact.value] = by_ci.get(r.context_impact.value, 0) + 1
            risks.append(r.enriched_risk_score)
            if r.context_age_hours > 168 and r.entity_id not in stale_ids:
                stale_ids.append(r.entity_id)
        avg_r = round(sum(risks) / len(risks), 4) if risks else 0.0
        recs: list[str] = []
        if stale_ids:
            recs.append(f"{len(stale_ids)} entities have stale context data")
        if not recs:
            recs.append("Context enrichment data is current")
        return RiskContextReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_enriched_risk=avg_r,
            by_context_type=by_ct,
            by_enrichment_source=by_es,
            by_context_impact=by_ci,
            stale_context_entity_ids=stale_ids[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        ct_dist: dict[str, int] = {}
        for r in self._records:
            ct_dist[r.context_type.value] = ct_dist.get(r.context_type.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "context_type_distribution": ct_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("risk_context_enrichment_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def enrich_risk_with_context(self) -> list[dict[str, Any]]:
        """Enrich entity risk scores with contextual amplification/mitigation."""
        impact_multipliers = {
            ContextImpact.AMPLIFYING: 1.3,
            ContextImpact.NEUTRAL: 1.0,
            ContextImpact.MITIGATING: 0.7,
            ContextImpact.OVERRIDING: 1.0,
        }
        entity_recs: dict[str, list[RiskContextRecord]] = {}
        for r in self._records:
            entity_recs.setdefault(r.entity_id, []).append(r)
        results: list[dict[str, Any]] = []
        for eid, recs in entity_recs.items():
            base = recs[-1].base_risk_score
            multiplier = 1.0
            for r in recs:
                if r.context_impact == ContextImpact.OVERRIDING:
                    base = r.enriched_risk_score
                    multiplier = 1.0
                    break
                multiplier *= impact_multipliers.get(r.context_impact, 1.0)
            enriched = round(base * multiplier, 4)
            results.append(
                {
                    "entity_id": eid,
                    "base_risk": base,
                    "enriched_risk": enriched,
                    "enrichment_multiplier": round(multiplier, 4),
                    "context_count": len(recs),
                }
            )
        results.sort(key=lambda x: x["enriched_risk"], reverse=True)
        return results

    def detect_missing_context(self) -> list[dict[str, Any]]:
        """Detect entities that are missing one or more context types."""
        all_types = {ct.value for ct in ContextType}
        entity_types: dict[str, set[str]] = {}
        for r in self._records:
            entity_types.setdefault(r.entity_id, set()).add(r.context_type.value)
        results: list[dict[str, Any]] = []
        for eid, types_present in entity_types.items():
            missing = list(all_types - types_present)
            if missing:
                results.append(
                    {
                        "entity_id": eid,
                        "missing_context_types": missing,
                        "missing_count": len(missing),
                        "coverage_pct": round(len(types_present) / len(all_types) * 100, 2),
                    }
                )
        results.sort(key=lambda x: x["missing_count"], reverse=True)
        return results

    def evaluate_context_freshness(self, stale_hours: float = 168.0) -> list[dict[str, Any]]:
        """Evaluate freshness of context data per entity and type."""
        entity_freshness: dict[str, dict[str, float]] = {}
        for r in self._records:
            entity_freshness.setdefault(r.entity_id, {})[r.context_type.value] = r.context_age_hours
        results: list[dict[str, Any]] = []
        for eid, type_ages in entity_freshness.items():
            stale_types = [t for t, age in type_ages.items() if age > stale_hours]
            max_age = max(type_ages.values()) if type_ages else 0.0
            results.append(
                {
                    "entity_id": eid,
                    "max_context_age_hours": round(max_age, 2),
                    "stale_context_types": stale_types,
                    "stale_count": len(stale_types),
                    "all_fresh": len(stale_types) == 0,
                }
            )
        results.sort(key=lambda x: x["max_context_age_hours"], reverse=True)
        return results
