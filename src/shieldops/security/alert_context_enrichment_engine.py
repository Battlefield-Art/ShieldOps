"""Alert Context Enrichment Engine — multi-source enrichment."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EnrichmentSource(StrEnum):
    THREAT_FEED = "threat_feed"
    ASSET_INVENTORY = "asset_inventory"
    IDENTITY_PROVIDER = "identity_provider"
    VULNERABILITY_DB = "vulnerability_db"
    GEO_INTELLIGENCE = "geo_intelligence"


class EnrichmentQuality(StrEnum):
    HIGH_FIDELITY = "high_fidelity"
    MEDIUM_FIDELITY = "medium_fidelity"
    LOW_FIDELITY = "low_fidelity"
    STALE = "stale"
    UNAVAILABLE = "unavailable"


class ContextRelevance(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    IRRELEVANT = "irrelevant"


# --- Models ---


class ContextEnrichmentRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str = ""
    source: EnrichmentSource = EnrichmentSource.THREAT_FEED
    quality: EnrichmentQuality = EnrichmentQuality.HIGH_FIDELITY
    relevance: ContextRelevance = ContextRelevance.HIGH
    enrichment_latency_ms: float = 0.0
    fields_added: int = 0
    source_freshness_hours: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ContextEnrichmentAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str = ""
    source: EnrichmentSource = EnrichmentSource.THREAT_FEED
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ContextEnrichmentReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_latency_ms: float = 0.0
    avg_fields_added: float = 0.0
    by_source: dict[str, int] = Field(default_factory=dict)
    by_quality: dict[str, int] = Field(default_factory=dict)
    by_relevance: dict[str, int] = Field(default_factory=dict)
    source_rankings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AlertContextEnrichmentEngine:
    """Track contextual enrichment from sources."""

    def __init__(
        self,
        max_records: int = 200000,
        quality_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._quality_threshold = quality_threshold
        self._records: list[ContextEnrichmentRecord] = []
        self._analyses: list[ContextEnrichmentAnalysis] = []
        logger.info(
            "alert_context_enrichment.init",
            max_records=max_records,
        )

    # -- record --

    def add_record(
        self,
        alert_id: str = "",
        source: EnrichmentSource = (EnrichmentSource.THREAT_FEED),
        quality: EnrichmentQuality = (EnrichmentQuality.HIGH_FIDELITY),
        relevance: ContextRelevance = (ContextRelevance.HIGH),
        enrichment_latency_ms: float = 0.0,
        fields_added: int = 0,
        source_freshness_hours: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ContextEnrichmentRecord:
        record = ContextEnrichmentRecord(
            alert_id=alert_id,
            source=source,
            quality=quality,
            relevance=relevance,
            enrichment_latency_ms=(enrichment_latency_ms),
            fields_added=fields_added,
            source_freshness_hours=(source_freshness_hours),
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "alert_context_enrichment.recorded",
            record_id=record.id,
        )
        return record

    # -- process --

    def process(self, alert_id: str) -> ContextEnrichmentAnalysis:
        relevant = [r for r in self._records if r.alert_id == alert_id]
        if not relevant:
            analysis = ContextEnrichmentAnalysis(
                alert_id=alert_id,
                description="no records found",
            )
            self._analyses.append(analysis)
            return analysis
        high_q = sum(
            1
            for r in relevant
            if r.quality
            in (
                EnrichmentQuality.HIGH_FIDELITY,
                EnrichmentQuality.MEDIUM_FIDELITY,
            )
        )
        rate = (high_q / len(relevant)) * 100
        breached = rate < self._quality_threshold
        analysis = ContextEnrichmentAnalysis(
            alert_id=alert_id,
            analysis_score=round(rate, 2),
            threshold=self._quality_threshold,
            breached=breached,
            description=(f"quality_rate={round(rate, 2)}%"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain methods --

    def enrich_from_source(
        self,
    ) -> dict[str, Any]:
        """Enrichment stats by source."""
        src_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.source.value
            src_data.setdefault(key, []).append(r.enrichment_latency_ms)
        result: dict[str, Any] = {}
        for src, lats in src_data.items():
            result[src] = {
                "count": len(lats),
                "avg_latency_ms": round(sum(lats) / len(lats), 2),
            }
        return result

    def calculate_enrichment_value(
        self,
    ) -> dict[str, Any]:
        """Value score by source (fields/latency)."""
        src_data: dict[str, dict[str, list[float]]] = {}
        for r in self._records:
            key = r.source.value
            src_data.setdefault(
                key,
                {"fields": [], "latency": []},
            )
            src_data[key]["fields"].append(float(r.fields_added))
            src_data[key]["latency"].append(r.enrichment_latency_ms)
        result: dict[str, Any] = {}
        for src, data in src_data.items():
            avg_f = sum(data["fields"]) / len(data["fields"])
            avg_l = sum(data["latency"]) / len(data["latency"])
            value = avg_f / (avg_l / 1000) if avg_l > 0 else avg_f
            result[src] = {
                "avg_fields": round(avg_f, 2),
                "avg_latency_ms": round(avg_l, 2),
                "value_score": round(value, 2),
            }
        return result

    def rank_sources(
        self,
    ) -> list[dict[str, Any]]:
        """Rank sources by quality and relevance."""
        src_scores: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.source.value
            src_scores.setdefault(
                key,
                {"total": 0, "high_quality": 0},
            )
            src_scores[key]["total"] += 1
            if r.quality in (
                EnrichmentQuality.HIGH_FIDELITY,
                EnrichmentQuality.MEDIUM_FIDELITY,
            ):
                src_scores[key]["high_quality"] += 1
        results: list[dict[str, Any]] = []
        for src, data in src_scores.items():
            rate = 0.0
            if data["total"] > 0:
                rate = data["high_quality"] / data["total"] * 100
            results.append(
                {
                    "source": src,
                    "quality_rate": round(rate, 2),
                    "total": data["total"],
                }
            )
        return sorted(
            results,
            key=lambda x: x["quality_rate"],
            reverse=True,
        )

    # -- report / stats --

    def generate_report(
        self,
    ) -> ContextEnrichmentReport:
        by_src: dict[str, int] = {}
        by_q: dict[str, int] = {}
        by_r: dict[str, int] = {}
        for r in self._records:
            by_src[r.source.value] = by_src.get(r.source.value, 0) + 1
            by_q[r.quality.value] = by_q.get(r.quality.value, 0) + 1
            by_r[r.relevance.value] = by_r.get(r.relevance.value, 0) + 1
        lats = [r.enrichment_latency_ms for r in self._records]
        avg_lat = round(sum(lats) / len(lats), 2) if lats else 0.0
        fields = [r.fields_added for r in self._records]
        avg_fields = round(sum(fields) / len(fields), 2) if fields else 0.0
        rankings = self.rank_sources()
        src_names = [r["source"] for r in rankings]
        recs: list[str] = []
        if avg_lat > 500.0:
            recs.append(f"Avg latency {avg_lat}ms exceeds 500ms")
        if avg_fields < 3.0:
            recs.append(f"Avg fields {avg_fields} below 3")
        if not recs:
            recs.append("Alert enrichment is healthy")
        return ContextEnrichmentReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_latency_ms=avg_lat,
            avg_fields_added=avg_fields,
            by_source=by_src,
            by_quality=by_q,
            by_relevance=by_r,
            source_rankings=src_names,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "quality_threshold": (self._quality_threshold),
            "unique_alerts": len({r.alert_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("alert_context_enrichment.cleared")
        return {"status": "cleared"}
