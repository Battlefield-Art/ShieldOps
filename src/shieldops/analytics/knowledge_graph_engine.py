"""KnowledgeGraphEngine — Build and query an agent knowledge graph."""

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
    SERVICE = "service"
    INFRASTRUCTURE = "infrastructure"
    INCIDENT = "incident"
    RUNBOOK = "runbook"
    PERSON = "person"


class RelationshipType(StrEnum):
    DEPENDS_ON = "depends_on"
    CAUSES = "causes"
    RESOLVES = "resolves"
    OWNS = "owns"
    MONITORS = "monitors"


class GraphHealth(StrEnum):
    CONNECTED = "connected"
    FRAGMENTED = "fragmented"
    STALE = "stale"


# --- Models ---


class KnowledgeGraphRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    entity_type: EntityType = EntityType.SERVICE
    relationship: RelationshipType = RelationshipType.DEPENDS_ON
    health: GraphHealth = GraphHealth.CONNECTED
    score: float = 0.0
    edge_count: int = 0
    staleness_days: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class KnowledgeGraphAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    entity_type: EntityType = EntityType.SERVICE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class KnowledgeGraphReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_entity_type: dict[str, int] = Field(default_factory=dict)
    by_relationship: dict[str, int] = Field(default_factory=dict)
    by_health: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class KnowledgeGraphEngine:
    """Build and query an agent knowledge graph."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[KnowledgeGraphRecord] = []
        self._analyses: list[KnowledgeGraphAnalysis] = []
        logger.info(
            "knowledge_graph_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        entity_type: EntityType = EntityType.SERVICE,
        relationship: RelationshipType = RelationshipType.DEPENDS_ON,
        health: GraphHealth = GraphHealth.CONNECTED,
        score: float = 0.0,
        edge_count: int = 0,
        staleness_days: int = 0,
        service: str = "",
        team: str = "",
    ) -> KnowledgeGraphRecord:
        record = KnowledgeGraphRecord(
            name=name,
            entity_type=entity_type,
            relationship=relationship,
            health=health,
            score=score,
            edge_count=edge_count,
            staleness_days=staleness_days,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "knowledge_graph_engine.record_added",
            record_id=record.id,
            name=name,
            entity_type=entity_type.value,
            relationship=relationship.value,
        )
        return record

    def get_record(self, record_id: str) -> KnowledgeGraphRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        entity_type: EntityType | None = None,
        health: GraphHealth | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[KnowledgeGraphRecord]:
        results = list(self._records)
        if entity_type is not None:
            results = [r for r in results if r.entity_type == entity_type]
        if health is not None:
            results = [r for r in results if r.health == health]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        entity_type: EntityType = EntityType.SERVICE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> KnowledgeGraphAnalysis:
        analysis = KnowledgeGraphAnalysis(
            name=name,
            entity_type=entity_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "knowledge_graph_engine.analysis_added",
            name=name,
            entity_type=entity_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_knowledge_islands(self) -> list[dict[str, Any]]:
        """Identify isolated nodes/clusters with few connections."""
        entity_edges: dict[str, dict[str, Any]] = {}
        for r in self._records:
            if r.name not in entity_edges:
                entity_edges[r.name] = {
                    "edge_count": 0,
                    "entity_type": r.entity_type.value,
                    "service": r.service,
                    "health": r.health.value,
                }
            entity_edges[r.name]["edge_count"] += r.edge_count
        islands: list[dict[str, Any]] = []
        for entity, data in entity_edges.items():
            if data["edge_count"] <= 1:
                islands.append(
                    {
                        "entity": entity,
                        "entity_type": data["entity_type"],
                        "edge_count": data["edge_count"],
                        "service": data["service"],
                        "isolation": "complete" if data["edge_count"] == 0 else "near",
                    }
                )
        return sorted(islands, key=lambda x: x["edge_count"])

    def compute_graph_connectivity(self) -> dict[str, Any]:
        """Compute overall graph connectivity metrics."""
        if not self._records:
            return {
                "total_entities": 0,
                "total_edges": 0,
                "avg_edges_per_entity": 0.0,
                "connectivity_score": 0.0,
                "health_distribution": {},
            }
        entities = {r.name for r in self._records}
        total_edges = sum(r.edge_count for r in self._records)
        avg_edges = round(total_edges / len(entities), 2) if entities else 0.0
        health_dist: dict[str, int] = {}
        for r in self._records:
            h = r.health.value
            health_dist[h] = health_dist.get(h, 0) + 1
        connected = health_dist.get("connected", 0)
        total = len(self._records)
        connectivity_score = round(connected / total * 100, 1) if total > 0 else 0.0
        return {
            "total_entities": len(entities),
            "total_edges": total_edges,
            "avg_edges_per_entity": avg_edges,
            "connectivity_score": connectivity_score,
            "health_distribution": health_dist,
        }

    def recommend_knowledge_gaps(self) -> list[dict[str, Any]]:
        """Recommend areas where knowledge graph needs enrichment."""
        recommendations: list[dict[str, Any]] = []
        # Stale nodes
        stale = [r for r in self._records if r.health == GraphHealth.STALE]
        svc_stale: dict[str, int] = {}
        for r in stale:
            svc_stale[r.service] = svc_stale.get(r.service, 0) + 1
        for svc, count in svc_stale.items():
            recommendations.append(
                {
                    "service": svc,
                    "issue": "stale_knowledge",
                    "count": count,
                    "priority": "high",
                    "suggestion": f"Refresh {count} stale knowledge entries for {svc}",
                }
            )
        # Entity types with low coverage
        type_counts: dict[str, int] = {}
        for r in self._records:
            type_counts[r.entity_type.value] = type_counts.get(r.entity_type.value, 0) + 1
        all_types = {t.value for t in EntityType}
        for t in all_types:
            if t not in type_counts:
                recommendations.append(
                    {
                        "service": "",
                        "issue": "missing_entity_type",
                        "count": 0,
                        "priority": "medium",
                        "suggestion": f"Add {t} entities to knowledge graph",
                    }
                )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else 1 if x["priority"] == "medium" else 2,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.entity_type.value
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
                        "entity_type": r.entity_type.value,
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

    def generate_report(self) -> KnowledgeGraphReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.entity_type.value] = by_e1.get(r.entity_type.value, 0) + 1
            by_e2[r.relationship.value] = by_e2.get(r.relationship.value, 0) + 1
            by_e3[r.health.value] = by_e3.get(r.health.value, 0) + 1
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
            recs.append("Knowledge Graph Engine is healthy")
        return KnowledgeGraphReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_entity_type=by_e1,
            by_relationship=by_e2,
            by_health=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("knowledge_graph_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.entity_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "entity_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
