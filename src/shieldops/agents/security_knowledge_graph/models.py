"""Security Knowledge Graph Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SKGStage(StrEnum):
    INGEST_ENTITIES = "ingest_entities"
    BUILD_RELATIONSHIPS = "build_relationships"
    ANALYZE_PATHS = "analyze_paths"
    DETECT_PATTERNS = "detect_patterns"
    QUERY_INSIGHTS = "query_insights"
    REPORT = "report"


class EntityType(StrEnum):
    ASSET = "asset"
    VULNERABILITY = "vulnerability"
    THREAT = "threat"
    CONTROL = "control"
    IDENTITY = "identity"
    NETWORK = "network"


class RelationshipType(StrEnum):
    EXPLOITS = "exploits"
    MITIGATES = "mitigates"
    CONNECTS_TO = "connects_to"
    OWNS = "owns"
    DEPENDS_ON = "depends_on"
    TARGETS = "targets"


class GraphEntity(BaseModel):
    """A node in the security knowledge graph."""

    id: str = ""
    name: str = ""
    entity_type: EntityType = EntityType.ASSET
    properties: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    tags: list[str] = Field(default_factory=list)


class GraphRelationship(BaseModel):
    """An edge in the security knowledge graph."""

    id: str = ""
    source_id: str = ""
    target_id: str = ""
    relationship_type: RelationshipType = RelationshipType.CONNECTS_TO
    weight: float = 1.0
    evidence: list[str] = Field(default_factory=list)


class AttackPath(BaseModel):
    """A discovered attack path through the graph."""

    id: str = ""
    path_nodes: list[str] = Field(default_factory=list)
    total_risk: float = 0.0
    exploitability: float = 0.0
    impact: str = "medium"
    description: str = ""


class GraphPattern(BaseModel):
    """A detected pattern in the knowledge graph."""

    id: str = ""
    pattern_type: str = ""
    entities_involved: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    severity: str = "medium"
    description: str = ""


class QueryResult(BaseModel):
    """Result from a knowledge graph query."""

    id: str = ""
    query: str = ""
    result_count: int = 0
    entities: list[str] = Field(default_factory=list)
    insights: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityKnowledgeGraphState(BaseModel):
    """Main state for the Security Knowledge Graph agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SKGStage = SKGStage.INGEST_ENTITIES

    entities: list[dict[str, Any]] = Field(default_factory=list)
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    attack_paths: list[dict[str, Any]] = Field(default_factory=list)
    patterns: list[dict[str, Any]] = Field(default_factory=list)
    query_results: list[dict[str, Any]] = Field(default_factory=list)

    report: str = ""
    total_entities: int = 0
    total_relationships: int = 0
    attack_paths_found: int = 0

    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
