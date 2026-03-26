"""Threat Intel Correlator — indicator correlation, relevance scoring, hunt queries."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class IntelFormat(StrEnum):
    STIX = "stix"
    MISP = "misp"
    OPENIOC = "openioc"
    CSV = "csv"
    JSON = "json"


class CorrelationMethod(StrEnum):
    EXACT_MATCH = "exact_match"
    FUZZY_MATCH = "fuzzy_match"
    BEHAVIORAL = "behavioral"
    GRAPH_BASED = "graph_based"
    ML_CLUSTERING = "ml_clustering"


class ActionPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# --- Models ---


class CorrelatorRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    indicator_name: str = ""
    intel_format: IntelFormat = IntelFormat.STIX
    correlation_method: CorrelationMethod = CorrelationMethod.EXACT_MATCH
    action_priority: ActionPriority = ActionPriority.MEDIUM
    relevance_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CorrelatorAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    indicator_name: str = ""
    intel_format: IntelFormat = IntelFormat.STIX
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CorrelatorReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    low_relevance_count: int = 0
    avg_relevance_score: float = 0.0
    by_format: dict[str, int] = Field(default_factory=dict)
    by_method: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    top_low_relevance: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ThreatIntelCorrelator:
    """Indicator correlation, relevance scoring, and hunt query generation."""

    def __init__(
        self,
        max_records: int = 200000,
        relevance_threshold: float = 60.0,
    ) -> None:
        self._max_records = max_records
        self._relevance_threshold = relevance_threshold
        self._records: list[CorrelatorRecord] = []
        self._analyses: list[CorrelatorAnalysis] = []
        logger.info(
            "threat_intel_correlator.initialized",
            max_records=max_records,
            relevance_threshold=relevance_threshold,
        )

    # -- record / get / list ----------------------------

    def add_record(
        self,
        indicator_name: str,
        intel_format: IntelFormat = IntelFormat.STIX,
        correlation_method: CorrelationMethod = (CorrelationMethod.EXACT_MATCH),
        action_priority: ActionPriority = (ActionPriority.MEDIUM),
        relevance_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> CorrelatorRecord:
        record = CorrelatorRecord(
            indicator_name=indicator_name,
            intel_format=intel_format,
            correlation_method=correlation_method,
            action_priority=action_priority,
            relevance_score=relevance_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "threat_intel_correlator.record_added",
            record_id=record.id,
            indicator_name=indicator_name,
            intel_format=intel_format.value,
        )
        return record

    def get_record(self, record_id: str) -> CorrelatorRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        intel_format: IntelFormat | None = None,
        action_priority: ActionPriority | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CorrelatorRecord]:
        results = list(self._records)
        if intel_format is not None:
            results = [r for r in results if r.intel_format == intel_format]
        if action_priority is not None:
            results = [r for r in results if r.action_priority == action_priority]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        indicator_name: str,
        intel_format: IntelFormat = IntelFormat.STIX,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CorrelatorAnalysis:
        analysis = CorrelatorAnalysis(
            indicator_name=indicator_name,
            intel_format=intel_format,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "threat_intel_correlator.analysis_added",
            indicator_name=indicator_name,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ------------------------------

    def correlate_indicators(self) -> dict[str, Any]:
        """Group by correlation_method; return count and avg relevance."""
        method_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.correlation_method.value
            method_data.setdefault(key, []).append(r.relevance_score)
        result: dict[str, Any] = {}
        for method, scores in method_data.items():
            result[method] = {
                "count": len(scores),
                "avg_relevance": round(sum(scores) / len(scores), 2),
            }
        return result

    def score_relevance(self) -> list[dict[str, Any]]:
        """Return records below relevance_threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.relevance_score < self._relevance_threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "indicator_name": (r.indicator_name),
                        "intel_format": (r.intel_format.value),
                        "relevance_score": (r.relevance_score),
                        "service": r.service,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["relevance_score"],
        )

    def generate_hunting_queries(
        self,
    ) -> list[dict[str, Any]]:
        """Group by service, avg relevance, sort descending."""
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.relevance_score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_relevance": round(sum(scores) / len(scores), 2),
                    "indicator_count": len(scores),
                }
            )
        results.sort(
            key=lambda x: x["avg_relevance"],
            reverse=True,
        )
        return results

    # -- report / stats ---------------------------------

    def generate_report(self) -> CorrelatorReport:
        by_format: dict[str, int] = {}
        by_method: dict[str, int] = {}
        by_priority: dict[str, int] = {}
        for r in self._records:
            by_format[r.intel_format.value] = by_format.get(r.intel_format.value, 0) + 1
            by_method[r.correlation_method.value] = by_method.get(r.correlation_method.value, 0) + 1
            by_priority[r.action_priority.value] = by_priority.get(r.action_priority.value, 0) + 1
        low_count = sum(1 for r in self._records if r.relevance_score < self._relevance_threshold)
        scores = [r.relevance_score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        low_list = self.score_relevance()
        top_low = [o["indicator_name"] for o in low_list[:5]]
        recs: list[str] = []
        if low_count > 0:
            recs.append(
                f"{low_count} indicator(s) below relevance threshold ({self._relevance_threshold})"
            )
        if not recs:
            recs.append("Threat intel correlation is healthy")
        return CorrelatorReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            low_relevance_count=low_count,
            avg_relevance_score=avg,
            by_format=by_format,
            by_method=by_method,
            by_priority=by_priority,
            top_low_relevance=top_low,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("threat_intel_correlator.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        format_dist: dict[str, int] = {}
        for r in self._records:
            key = r.intel_format.value
            format_dist[key] = format_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "relevance_threshold": (self._relevance_threshold),
            "format_distribution": format_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
