"""Trust Relationship Engine — map and assess trust chains."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TrustType(StrEnum):
    OAUTH_DELEGATION = "oauth_delegation"
    ROLE_ASSUMPTION = "role_assumption"
    FEDERATION = "federation"
    API_KEY_SHARING = "api_key_sharing"
    CERTIFICATE_TRUST = "certificate_trust"
    AGENT_DELEGATION = "agent_delegation"


class TrustHealth(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    RISKY = "risky"
    BROKEN = "broken"
    UNKNOWN = "unknown"


class TrustDirection(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BIDIRECTIONAL = "bidirectional"
    TRANSITIVE = "transitive"


# --- Models ---


class TrustRelationshipRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_entity: str = ""
    target_entity: str = ""
    trust_type: TrustType = TrustType.OAUTH_DELEGATION
    trust_health: TrustHealth = TrustHealth.UNKNOWN
    trust_direction: TrustDirection = TrustDirection.OUTBOUND
    scope: str = ""
    expires_at: float = 0.0
    last_validated_at: float = 0.0
    details: str = ""
    created_at: float = Field(default_factory=time.time)


class TrustPath(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    path_entities: list[str] = Field(default_factory=list)
    path_length: int = 0
    weakest_link: str = ""
    overall_health: TrustHealth = TrustHealth.UNKNOWN
    is_transitive: bool = False
    risk_score: float = 0.0
    assessed_at: float = Field(default_factory=time.time)


class TrustReport(BaseModel):
    total_relationships: int = 0
    total_paths_traced: int = 0
    healthy_count: int = 0
    risky_count: int = 0
    broken_count: int = 0
    cycles_detected: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_health: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---

_HEALTH_SCORES: dict[TrustHealth, float] = {
    TrustHealth.HEALTHY: 0.0,
    TrustHealth.DEGRADED: 25.0,
    TrustHealth.RISKY: 50.0,
    TrustHealth.BROKEN: 100.0,
    TrustHealth.UNKNOWN: 40.0,
}


class TrustRelationshipEngine:
    """Map and assess trust chains across identity relationships."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[TrustRelationshipRecord] = []
        self._paths: list[TrustPath] = []
        logger.info("trust_relationship_engine.initialized", max_records=max_records)

    # -- record --------------------------------------------------------------

    def register_relationship(
        self,
        source_entity: str,
        target_entity: str,
        trust_type: TrustType = TrustType.OAUTH_DELEGATION,
        trust_health: TrustHealth = TrustHealth.UNKNOWN,
        trust_direction: TrustDirection = TrustDirection.OUTBOUND,
        scope: str = "",
        expires_at: float = 0.0,
        details: str = "",
    ) -> TrustRelationshipRecord:
        record = TrustRelationshipRecord(
            source_entity=source_entity,
            target_entity=target_entity,
            trust_type=trust_type,
            trust_health=trust_health,
            trust_direction=trust_direction,
            scope=scope,
            expires_at=expires_at,
            details=details,
            last_validated_at=time.time(),
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "trust_relationship_engine.relationship_registered",
            record_id=record.id,
            source=source_entity,
            target=target_entity,
            trust_type=trust_type.value,
        )
        return record

    # -- domain operations ---------------------------------------------------

    def trace_trust_path(self, start_entity: str, end_entity: str) -> TrustPath:
        """Trace the trust path between two entities using BFS."""
        adjacency: dict[str, list[tuple[str, TrustRelationshipRecord]]] = {}
        for r in self._records:
            adjacency.setdefault(r.source_entity, []).append((r.target_entity, r))
            if r.trust_direction == TrustDirection.BIDIRECTIONAL:
                adjacency.setdefault(r.target_entity, []).append((r.source_entity, r))

        # BFS
        visited: set[str] = set()
        queue: list[tuple[str, list[str], list[TrustRelationshipRecord]]] = [
            (start_entity, [start_entity], [])
        ]
        visited.add(start_entity)

        while queue:
            current, path, rels = queue.pop(0)
            if current == end_entity:
                # Compute health
                healths = [r.trust_health for r in rels]
                worst = (
                    max(healths, key=lambda h: _HEALTH_SCORES.get(h, 50.0))
                    if healths
                    else TrustHealth.UNKNOWN
                )
                risk = max((_HEALTH_SCORES.get(h, 50.0) for h in healths), default=0.0)
                weakest = ""
                for r in rels:
                    if r.trust_health == worst:
                        weakest = f"{r.source_entity}->{r.target_entity}"
                        break

                tp = TrustPath(
                    path_entities=path,
                    path_length=len(path) - 1,
                    weakest_link=weakest,
                    overall_health=worst,
                    is_transitive=len(path) > 2,
                    risk_score=round(risk, 2),
                )
                self._paths.append(tp)
                if len(self._paths) > self._max_records:
                    self._paths = self._paths[-self._max_records :]
                return tp

            for neighbor, rel in adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, [*path, neighbor], [*rels, rel]))

        # No path found
        return TrustPath(
            path_entities=[start_entity],
            path_length=0,
            overall_health=TrustHealth.BROKEN,
            risk_score=100.0,
        )

    def detect_transitive_risks(self) -> list[dict[str, Any]]:
        """Find trust relationships that create transitive risk chains."""
        # Build adjacency and find paths of length > 1
        adjacency: dict[str, list[str]] = {}
        for r in self._records:
            adjacency.setdefault(r.source_entity, []).append(r.target_entity)

        results: list[dict[str, Any]] = []
        for entity, targets in adjacency.items():
            for target in targets:
                # Check if target has further outbound trusts
                transitive_targets = adjacency.get(target, [])
                if transitive_targets:
                    for tt in transitive_targets:
                        results.append(
                            {
                                "chain": [entity, target, tt],
                                "chain_length": 2,
                                "origin": entity,
                                "terminal": tt,
                                "risk": "transitive_trust_delegation",
                            }
                        )
        return results[:100]  # Cap results

    def find_trust_cycles(self) -> list[dict[str, Any]]:
        """Detect circular trust relationships using DFS."""
        adjacency: dict[str, list[str]] = {}
        for r in self._records:
            adjacency.setdefault(r.source_entity, []).append(r.target_entity)

        cycles: list[list[str]] = []
        visited: set[str] = set()
        rec_stack: set[str] = set()

        def _dfs(node: str, path: list[str]) -> None:
            visited.add(node)
            rec_stack.add(node)
            for neighbor in adjacency.get(node, []):
                if neighbor not in visited:
                    _dfs(neighbor, [*path, neighbor])
                elif neighbor in rec_stack:
                    # Found cycle
                    cycle_start = path.index(neighbor) if neighbor in path else 0
                    cycles.append(path[cycle_start:] + [neighbor])
            rec_stack.discard(node)

        for entity in adjacency:
            if entity not in visited:
                _dfs(entity, [entity])

        results: list[dict[str, Any]] = []
        for cycle in cycles[:50]:
            results.append(
                {
                    "cycle": cycle,
                    "cycle_length": len(cycle) - 1,
                    "risk": "circular_trust_dependency",
                }
            )
        return results

    # -- report / stats ------------------------------------------------------

    def generate_trust_report(self) -> TrustReport:
        by_type: dict[str, int] = {}
        by_health: dict[str, int] = {}
        for r in self._records:
            by_type[r.trust_type.value] = by_type.get(r.trust_type.value, 0) + 1
            by_health[r.trust_health.value] = by_health.get(r.trust_health.value, 0) + 1

        healthy = sum(1 for r in self._records if r.trust_health == TrustHealth.HEALTHY)
        risky = sum(1 for r in self._records if r.trust_health == TrustHealth.RISKY)
        broken = sum(1 for r in self._records if r.trust_health == TrustHealth.BROKEN)
        cycles = self.find_trust_cycles()

        recs: list[str] = []
        if broken:
            recs.append(f"{broken} broken trust relationship(s) require remediation")
        if risky:
            recs.append(f"{risky} risky trust relationship(s) should be reviewed")
        if cycles:
            recs.append(f"{len(cycles)} circular trust dependencies detected")
        transitive = self.detect_transitive_risks()
        if transitive:
            recs.append(f"{len(transitive)} transitive trust chains found")
        if not recs:
            recs.append("Trust relationship health meets targets")

        return TrustReport(
            total_relationships=len(self._records),
            total_paths_traced=len(self._paths),
            healthy_count=healthy,
            risky_count=risky,
            broken_count=broken,
            cycles_detected=len(cycles),
            by_type=by_type,
            by_health=by_health,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            type_dist[r.trust_type.value] = type_dist.get(r.trust_type.value, 0) + 1
        return {
            "total_relationships": len(self._records),
            "total_paths_traced": len(self._paths),
            "type_distribution": type_dist,
            "unique_entities": len(
                {r.source_entity for r in self._records} | {r.target_entity for r in self._records}
            ),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._paths.clear()
        logger.info("trust_relationship_engine.cleared")
        return {"status": "cleared"}
