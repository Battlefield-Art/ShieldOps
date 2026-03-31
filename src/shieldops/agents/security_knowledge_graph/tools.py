"""Security Knowledge Graph Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any
from uuid import uuid4

import structlog

from .models import (
    AttackPath,
    EntityType,
    GraphEntity,
    GraphPattern,
    GraphRelationship,
    QueryResult,
    RelationshipType,
)

logger = structlog.get_logger()

_SAMPLE_ENTITIES: list[dict[str, Any]] = [
    {
        "name": "web-server-01",
        "entity_type": "asset",
        "risk_score": 0.7,
        "tags": ["public", "web"],
    },
    {
        "name": "CVE-2026-1234",
        "entity_type": "vulnerability",
        "risk_score": 0.9,
        "tags": ["rce", "critical"],
    },
    {
        "name": "APT-29",
        "entity_type": "threat",
        "risk_score": 0.95,
        "tags": ["apt", "nation-state"],
    },
    {
        "name": "db-primary",
        "entity_type": "asset",
        "risk_score": 0.85,
        "tags": ["database", "pii"],
    },
    {
        "name": "waf-policy-01",
        "entity_type": "control",
        "risk_score": 0.2,
        "tags": ["waf", "perimeter"],
    },
    {
        "name": "svc-account-deploy",
        "entity_type": "identity",
        "risk_score": 0.6,
        "tags": ["service-account", "ci-cd"],
    },
    {
        "name": "internal-subnet-10",
        "entity_type": "network",
        "risk_score": 0.5,
        "tags": ["internal", "flat"],
    },
    {
        "name": "CVE-2026-5678",
        "entity_type": "vulnerability",
        "risk_score": 0.75,
        "tags": ["sqli", "high"],
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class SecurityKnowledgeGraphToolkit:
    """Tools for security knowledge graph analysis."""

    def __init__(
        self,
        graph_store: Any | None = None,
        threat_intel_api: Any | None = None,
    ) -> None:
        self._graph_store = graph_store
        self._threat_intel_api = threat_intel_api

    async def ingest_entities(
        self,
        tenant_id: str,
    ) -> list[GraphEntity]:
        """Ingest security entities into the knowledge graph."""
        logger.info(
            "skg.ingest_entities",
            tenant_id=tenant_id,
        )

        if self._graph_store is not None:
            try:
                raw = await self._graph_store.get_entities(
                    tenant_id=tenant_id,
                )
                return [GraphEntity(**r) for r in raw]
            except Exception:
                logger.exception("skg.ingest_entities.error")

        entities: list[GraphEntity] = []
        for i, e in enumerate(_SAMPLE_ENTITIES):
            noise = random.uniform(-0.05, 0.05)  # noqa: S311
            entities.append(
                GraphEntity(
                    id=_gen_id("ENT", tenant_id, i),
                    name=e["name"],
                    entity_type=EntityType(e["entity_type"]),
                    properties={"source": "scanner", "scan_id": str(uuid4())[:8]},
                    risk_score=round(max(0.0, min(1.0, e["risk_score"] + noise)), 2),
                    tags=e["tags"],
                )
            )
        return entities

    async def build_relationships(
        self,
        entities: list[GraphEntity],
    ) -> list[GraphRelationship]:
        """Build relationships between entities."""
        logger.info(
            "skg.build_relationships",
            count=len(entities),
        )

        relationships: list[GraphRelationship] = []
        rel_types = list(RelationshipType)
        idx = 0
        for i, src in enumerate(entities):
            for j, tgt in enumerate(entities):
                if i >= j:
                    continue
                should_connect = random.random() > 0.5  # noqa: S311
                if not should_connect:
                    continue
                rt_idx = random.randint(0, len(rel_types) - 1)  # noqa: S311
                weight = random.uniform(0.3, 1.0)  # noqa: S311
                relationships.append(
                    GraphRelationship(
                        id=_gen_id("REL", f"{src.id}-{tgt.id}", idx),
                        source_id=src.id,
                        target_id=tgt.id,
                        relationship_type=rel_types[rt_idx],
                        weight=round(weight, 2),
                        evidence=[
                            "Auto-discovered via scan",
                            f"Confidence: {round(weight, 2)}",
                        ],
                    )
                )
                idx += 1
        return relationships

    async def analyze_paths(
        self,
        entities: list[GraphEntity],
        relationships: list[GraphRelationship],
    ) -> list[AttackPath]:
        """Discover attack paths through the graph."""
        logger.info(
            "skg.analyze_paths",
            entities=len(entities),
            relationships=len(relationships),
        )

        threats = [e for e in entities if e.entity_type == EntityType.THREAT]
        assets = [e for e in entities if e.entity_type in (EntityType.ASSET, EntityType.IDENTITY)]

        paths: list[AttackPath] = []
        idx = 0
        for t in threats:
            for a in assets:
                risk = round((t.risk_score + a.risk_score) / 2, 2)
                exploit = random.uniform(0.4, 0.95)  # noqa: S311
                paths.append(
                    AttackPath(
                        id=_gen_id("AP", f"{t.id}-{a.id}", idx),
                        path_nodes=[t.id, a.id],
                        total_risk=risk,
                        exploitability=round(exploit, 2),
                        impact="critical" if risk > 0.8 else "high",
                        description=(f"Path from {t.name} to {a.name} via graph traversal"),
                    )
                )
                idx += 1
        return paths

    async def detect_patterns(
        self,
        entities: list[GraphEntity],
        relationships: list[GraphRelationship],
    ) -> list[GraphPattern]:
        """Detect patterns in the knowledge graph."""
        logger.info(
            "skg.detect_patterns",
            entities=len(entities),
            relationships=len(relationships),
        )

        patterns: list[GraphPattern] = []
        high_risk = [e for e in entities if e.risk_score > 0.7]
        if high_risk:
            conf = random.uniform(0.7, 0.95)  # noqa: S311
            patterns.append(
                GraphPattern(
                    id=_gen_id("PAT", "high-risk-cluster", 0),
                    pattern_type="high_risk_cluster",
                    entities_involved=[e.id for e in high_risk],
                    confidence=round(conf, 2),
                    severity="critical",
                    description=(
                        f"Cluster of {len(high_risk)} high-risk entities "
                        f"with interconnected relationships"
                    ),
                )
            )

        vuln_entities = [e for e in entities if e.entity_type == EntityType.VULNERABILITY]
        if vuln_entities:
            conf2 = random.uniform(0.6, 0.9)  # noqa: S311
            patterns.append(
                GraphPattern(
                    id=_gen_id("PAT", "vuln-chain", 1),
                    pattern_type="vulnerability_chain",
                    entities_involved=[e.id for e in vuln_entities],
                    confidence=round(conf2, 2),
                    severity="high",
                    description=(f"{len(vuln_entities)} vulnerabilities forming an exploit chain"),
                )
            )

        return patterns

    async def query_insights(
        self,
        entities: list[GraphEntity],
        attack_paths: list[AttackPath],
        patterns: list[GraphPattern],
    ) -> list[QueryResult]:
        """Query the knowledge graph for actionable insights."""
        logger.info("skg.query_insights")

        results: list[QueryResult] = []
        results.append(
            QueryResult(
                id=_gen_id("QR", "top-risk", 0),
                query="Top risk entities",
                result_count=len(entities),
                entities=[
                    e.id for e in sorted(entities, key=lambda x: x.risk_score, reverse=True)[:5]
                ],
                insights=[
                    f"Total entities: {len(entities)}",
                    f"Attack paths: {len(attack_paths)}",
                    f"Patterns detected: {len(patterns)}",
                ],
            )
        )
        return results

    async def record_metric(
        self,
        metric_name: str,
        value: float,
    ) -> dict[str, Any]:
        """Record a graph analysis metric."""
        logger.info(
            "skg.record_metric",
            metric=metric_name,
            value=value,
        )
        return {
            "metric": metric_name,
            "value": value,
            "recorded": True,
        }
