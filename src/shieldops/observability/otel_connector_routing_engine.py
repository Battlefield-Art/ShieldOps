"""OtelConnectorRoutingEngine — route telemetry between pipelines via OTel connectors."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ConnectorType(StrEnum):
    COUNT = "count"
    SPANMETRICS = "spanmetrics"
    FORWARD = "forward"
    ROUTING = "routing"


class RoutingStrategy(StrEnum):
    ROUND_ROBIN = "round_robin"
    CONTENT_BASED = "content_based"
    PRIORITY = "priority"


class RoutingHealth(StrEnum):
    OPTIMAL = "optimal"
    SUBOPTIMAL = "suboptimal"
    BROKEN = "broken"


# --- Models ---


class OtelConnectorRoutingRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    connector_type: ConnectorType = ConnectorType.FORWARD
    routing_strategy: RoutingStrategy = RoutingStrategy.ROUND_ROBIN
    routing_health: RoutingHealth = RoutingHealth.OPTIMAL
    score: float = 0.0
    route_count: int = 0
    latency_ms: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelConnectorRoutingAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    connector_type: ConnectorType = ConnectorType.FORWARD
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelConnectorRoutingReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_connector_type: dict[str, int] = Field(default_factory=dict)
    by_routing_strategy: dict[str, int] = Field(default_factory=dict)
    by_routing_health: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OtelConnectorRoutingEngine:
    """Route telemetry between pipelines via OTel connectors."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OtelConnectorRoutingRecord] = []
        self._analyses: list[OtelConnectorRoutingAnalysis] = []
        logger.info(
            "otel_connector_routing_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        connector_type: ConnectorType = ConnectorType.FORWARD,
        routing_strategy: RoutingStrategy = RoutingStrategy.ROUND_ROBIN,
        routing_health: RoutingHealth = RoutingHealth.OPTIMAL,
        score: float = 0.0,
        route_count: int = 0,
        latency_ms: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> OtelConnectorRoutingRecord:
        record = OtelConnectorRoutingRecord(
            name=name,
            connector_type=connector_type,
            routing_strategy=routing_strategy,
            routing_health=routing_health,
            score=score,
            route_count=route_count,
            latency_ms=latency_ms,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel_connector_routing_engine.record_added",
            record_id=record.id,
            name=name,
            connector_type=connector_type.value,
            routing_health=routing_health.value,
        )
        return record

    def get_record(self, record_id: str) -> OtelConnectorRoutingRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        connector_type: ConnectorType | None = None,
        routing_health: RoutingHealth | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[OtelConnectorRoutingRecord]:
        results = list(self._records)
        if connector_type is not None:
            results = [r for r in results if r.connector_type == connector_type]
        if routing_health is not None:
            results = [r for r in results if r.routing_health == routing_health]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        connector_type: ConnectorType = ConnectorType.FORWARD,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> OtelConnectorRoutingAnalysis:
        analysis = OtelConnectorRoutingAnalysis(
            name=name,
            connector_type=connector_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel_connector_routing_engine.analysis_added",
            name=name,
            connector_type=connector_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def evaluate_routing_efficiency(self) -> list[dict[str, Any]]:
        """Evaluate routing efficiency per connector."""
        connector_data: dict[str, list[OtelConnectorRoutingRecord]] = {}
        for r in self._records:
            connector_data.setdefault(r.name, []).append(r)
        results: list[dict[str, Any]] = []
        for name, records in connector_data.items():
            scores = [r.score for r in records]
            latencies = [r.latency_ms for r in records]
            avg_score = sum(scores) / len(scores)
            avg_latency = sum(latencies) / len(latencies)
            results.append(
                {
                    "connector": name,
                    "avg_score": round(avg_score, 2),
                    "avg_latency_ms": round(avg_latency, 2),
                    "route_count": sum(r.route_count for r in records),
                    "efficiency": "high" if avg_score >= self._threshold else "low",
                }
            )
        return sorted(results, key=lambda x: x["avg_score"], reverse=True)

    def detect_routing_loops(self) -> list[dict[str, Any]]:
        """Detect potential routing loops in connector configurations."""
        svc_routes: dict[str, list[str]] = {}
        for r in self._records:
            if r.connector_type == ConnectorType.FORWARD:
                svc_routes.setdefault(r.service, []).append(r.name)
        loops: list[dict[str, Any]] = []
        for svc, connectors in svc_routes.items():
            if len(connectors) != len(set(connectors)):
                seen: dict[str, int] = {}
                for c in connectors:
                    seen[c] = seen.get(c, 0) + 1
                duplicates = {k: v for k, v in seen.items() if v > 1}
                loops.append(
                    {
                        "service": svc,
                        "suspected_loop_connectors": list(duplicates.keys()),
                        "occurrence_counts": duplicates,
                        "severity": "critical" if len(duplicates) > 1 else "warning",
                    }
                )
        return loops

    def optimize_connector_placement(self) -> list[dict[str, Any]]:
        """Suggest optimal connector placement for pipelines."""
        recommendations: list[dict[str, Any]] = []
        broken = [r for r in self._records if r.routing_health == RoutingHealth.BROKEN]
        for r in broken:
            recommendations.append(
                {
                    "connector": r.name,
                    "service": r.service,
                    "current_type": r.connector_type.value,
                    "issue": "broken_routing",
                    "suggestion": "Replace or reconfigure connector",
                    "priority": "high",
                }
            )
        suboptimal = [
            r
            for r in self._records
            if r.routing_health == RoutingHealth.SUBOPTIMAL and r.score < self._threshold
        ]
        for r in suboptimal:
            recommendations.append(
                {
                    "connector": r.name,
                    "service": r.service,
                    "current_type": r.connector_type.value,
                    "issue": "suboptimal_performance",
                    "suggestion": "Consider content-based routing for better efficiency",
                    "priority": "medium",
                }
            )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else 1,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.connector_type.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "connector_type": r.connector_type.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> OtelConnectorRoutingReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.connector_type.value] = by_e1.get(r.connector_type.value, 0) + 1
            by_e2[r.routing_strategy.value] = by_e2.get(r.routing_strategy.value, 0) + 1
            by_e3[r.routing_health.value] = by_e3.get(r.routing_health.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("OTel Connector Routing Engine is healthy")
        return OtelConnectorRoutingReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_connector_type=by_e1,
            by_routing_strategy=by_e2,
            by_routing_health=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel_connector_routing_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.connector_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "connector_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
