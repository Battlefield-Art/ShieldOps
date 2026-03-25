"""Alert Narrative Composer Engine — track and analyze alert-to-narrative composition quality."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class NarrativeType(StrEnum):
    SINGLE_ALERT = "single_alert"
    CORRELATED = "correlated"
    KILL_CHAIN = "kill_chain"
    CAMPAIGN = "campaign"
    INSIDER_THREAT = "insider_threat"


class CompositionQuality(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    MODERATE = "moderate"
    POOR = "poor"
    INCOMPLETE = "incomplete"


class AlertSource(StrEnum):
    EDR = "edr"
    SIEM = "siem"
    CLOUD = "cloud"
    IDENTITY = "identity"
    NETWORK = "network"


# --- Models ---


class NarrativeRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    situation_id: str = ""
    narrative_type: NarrativeType = NarrativeType.SINGLE_ALERT
    composition_quality: CompositionQuality = CompositionQuality.MODERATE
    alert_count: int = 0
    vendor_count: int = 0
    correlation_confidence: float = 0.0
    time_span_minutes: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class NarrativeAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    situation_id: str = ""
    narrative_type: NarrativeType = NarrativeType.SINGLE_ALERT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class NarrativeReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    poor_quality_count: int = 0
    avg_correlation_confidence: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_quality: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    top_complex: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AlertNarrativeComposerEngine:
    """Track and analyze alert-to-narrative composition quality."""

    def __init__(
        self,
        max_records: int = 200000,
        correlation_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = correlation_threshold
        self._records: list[NarrativeRecord] = []
        self._analyses: list[NarrativeAnalysis] = []
        logger.info(
            "alert_narrative_composer_engine.initialized",
            max_records=max_records,
            correlation_threshold=correlation_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        situation_id: str,
        narrative_type: NarrativeType = NarrativeType.SINGLE_ALERT,
        composition_quality: CompositionQuality = CompositionQuality.MODERATE,
        alert_count: int = 0,
        vendor_count: int = 0,
        correlation_confidence: float = 0.0,
        time_span_minutes: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> NarrativeRecord:
        record = NarrativeRecord(
            situation_id=situation_id,
            narrative_type=narrative_type,
            composition_quality=composition_quality,
            alert_count=alert_count,
            vendor_count=vendor_count,
            correlation_confidence=correlation_confidence,
            time_span_minutes=time_span_minutes,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "alert_narrative_composer_engine.record_added",
            record_id=record.id,
            situation_id=situation_id,
            narrative_type=narrative_type.value,
            composition_quality=composition_quality.value,
        )
        return record

    def get_record(self, record_id: str) -> NarrativeRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        narrative_type: NarrativeType | None = None,
        composition_quality: CompositionQuality | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[NarrativeRecord]:
        results = list(self._records)
        if narrative_type is not None:
            results = [r for r in results if r.narrative_type == narrative_type]
        if composition_quality is not None:
            results = [r for r in results if r.composition_quality == composition_quality]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        situation_id: str,
        narrative_type: NarrativeType = NarrativeType.SINGLE_ALERT,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> NarrativeAnalysis:
        analysis = NarrativeAnalysis(
            situation_id=situation_id,
            narrative_type=narrative_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "alert_narrative_composer_engine.analysis_added",
            situation_id=situation_id,
            narrative_type=narrative_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_narrative_quality(self) -> list[dict[str, Any]]:
        """Analyze narrative quality distribution by type."""
        type_data: dict[str, list[NarrativeRecord]] = {}
        for r in self._records:
            type_data.setdefault(r.narrative_type.value, []).append(r)
        results: list[dict[str, Any]] = []
        for ntype, records in type_data.items():
            confs = [r.correlation_confidence for r in records]
            avg_conf = round(sum(confs) / len(confs), 2) if confs else 0.0
            poor = sum(
                1
                for r in records
                if r.composition_quality in (CompositionQuality.POOR, CompositionQuality.INCOMPLETE)
            )
            results.append(
                {
                    "narrative_type": ntype,
                    "total_narratives": len(records),
                    "avg_correlation_confidence": avg_conf,
                    "poor_quality_count": poor,
                    "quality_grade": "excellent"
                    if avg_conf >= 90
                    else "good"
                    if avg_conf >= self._threshold
                    else "fair"
                    if avg_conf >= 50
                    else "poor",
                }
            )
        return sorted(results, key=lambda x: x["avg_correlation_confidence"])

    def identify_poor_compositions(self) -> list[dict[str, Any]]:
        """Identify narratives with poor composition quality."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.correlation_confidence < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "situation_id": r.situation_id,
                        "narrative_type": r.narrative_type.value,
                        "composition_quality": r.composition_quality.value,
                        "correlation_confidence": r.correlation_confidence,
                        "alert_count": r.alert_count,
                        "vendor_count": r.vendor_count,
                        "service": r.service,
                        "severity": "critical"
                        if r.correlation_confidence < 30
                        else "high"
                        if r.correlation_confidence < 50
                        else "medium",
                    }
                )
        return sorted(results, key=lambda x: x["correlation_confidence"])

    def detect_composition_trends(self) -> list[dict[str, Any]]:
        """Detect composition quality trends over time by team."""
        team_data: dict[str, list[NarrativeRecord]] = {}
        for r in self._records:
            team_data.setdefault(r.team, []).append(r)
        results: list[dict[str, Any]] = []
        for team_name, records in team_data.items():
            sorted_recs = sorted(records, key=lambda x: x.created_at)
            if len(sorted_recs) < 2:
                continue
            mid = len(sorted_recs) // 2
            first_half = sorted_recs[:mid]
            second_half = sorted_recs[mid:]
            avg_first = round(
                sum(r.correlation_confidence for r in first_half) / len(first_half),
                2,
            )
            avg_second = round(
                sum(r.correlation_confidence for r in second_half) / len(second_half),
                2,
            )
            delta = round(avg_second - avg_first, 2)
            results.append(
                {
                    "team": team_name,
                    "narrative_count": len(records),
                    "early_avg_confidence": avg_first,
                    "recent_avg_confidence": avg_second,
                    "delta": delta,
                    "trend": "improving" if delta > 5 else "stable" if delta > -5 else "declining",
                }
            )
        return sorted(results, key=lambda x: x["delta"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.situation_id == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        confs = [r.correlation_confidence for r in matched]
        avg = round(sum(confs) / len(confs), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_correlation_confidence": avg,
            "below_threshold": sum(1 for c in confs if c < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> NarrativeReport:
        by_type: dict[str, int] = {}
        by_quality: dict[str, int] = {}
        by_source: dict[str, int] = {}
        for r in self._records:
            by_type[r.narrative_type.value] = by_type.get(r.narrative_type.value, 0) + 1
            by_quality[r.composition_quality.value] = (
                by_quality.get(r.composition_quality.value, 0) + 1
            )
        # Aggregate alert sources from service field as proxy
        for r in self._records:
            svc_key = r.service if r.service else "unknown"
            by_source[svc_key] = by_source.get(svc_key, 0) + 1
        poor_quality_count = sum(
            1 for r in self._records if r.correlation_confidence < self._threshold
        )
        confs = [r.correlation_confidence for r in self._records]
        avg_conf = round(sum(confs) / len(confs), 2) if confs else 0.0
        poor_list = self.identify_poor_compositions()
        top_complex = [p["situation_id"] for p in poor_list[:5]]
        recs: list[str] = []
        if self._records and poor_quality_count > 0:
            recs.append(
                f"{poor_quality_count} narrative(s) below correlation threshold "
                f"({self._threshold}%)"
            )
        if self._records and avg_conf < self._threshold:
            recs.append(
                f"Avg correlation confidence {avg_conf}% below threshold ({self._threshold}%)"
            )
        if not recs:
            recs.append("Alert Narrative Composer Engine is healthy")
        return NarrativeReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            poor_quality_count=poor_quality_count,
            avg_correlation_confidence=avg_conf,
            by_type=by_type,
            by_quality=by_quality,
            by_source=by_source,
            top_complex=top_complex,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("alert_narrative_composer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            key = r.narrative_type.value
            type_dist[key] = type_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "correlation_threshold": self._threshold,
            "type_distribution": type_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
