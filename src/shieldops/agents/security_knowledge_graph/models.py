"""State models for the Security Knowledge Graph Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class SKGStage(StrEnum):
    """Workflow stages for security knowledge graph."""

    INGEST_ENTITIES = "ingest_entities"
    EXTRACT_RELATIONSHIPS = "extract_relationships"
    BUILD_GRAPH = "build_graph"
    QUERY_PATTERNS = "query_patterns"
    DETECT_ANOMALIES = "detect_anomalies"
    REPORT = "report"


class EntityType(StrEnum):
    """Types of security entities in the knowledge graph."""

    HOST = "host"
    USER = "user"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    THREAT_ACTOR = "threat_actor"
    INDICATOR = "indicator"
    POLICY = "policy"


class RelationshipType(StrEnum):
    """Types of relationships between security entities."""

    COMMUNICATES_WITH = "communicates_with"
    AUTHENTICATES_TO = "authenticates_to"
    EXPLOITS = "exploits"
    MITIGATES = "mitigates"
    DEPENDS_ON = "depends_on"
    OWNS = "owns"
    TARGETS = "targets"


# ── Domain Models ─────────────────────────────────────


class SecurityEntity(BaseModel):
    """An entity in the security knowledge graph."""

    entity_id: str = ""
    entity_type: EntityType = EntityType.HOST
    name: str = ""
    attributes: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    first_seen: str = ""
    last_seen: str = ""


class EntityRelationship(BaseModel):
    """A relationship between two security entities."""

    relationship_id: str = ""
    source_id: str = ""
    target_id: str = ""
    relationship_type: RelationshipType = RelationshipType.COMMUNICATES_WITH
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphPattern(BaseModel):
    """A pattern discovered in the knowledge graph."""

    pattern_id: str = ""
    name: str = ""
    description: str = ""
    entity_count: int = 0
    relationship_count: int = 0
    severity: str = ""
    indicators: list[str] = Field(default_factory=list)


class PatternMatch(BaseModel):
    """A match against a known threat pattern."""

    match_id: str = ""
    pattern_id: str = ""
    matched_entities: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    is_anomalous: bool = False
    details: str = ""


class KnowledgeReport(BaseModel):
    """Final report from knowledge graph analysis."""

    total_entities: int = 0
    total_relationships: int = 0
    patterns_found: int = 0
    anomalies_detected: int = 0
    risk_summary: str = ""
    recommendations: list[str] = Field(default_factory=list)


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the knowledge graph workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityKnowledgeGraphState(BaseModel):
    """Full state for the Security Knowledge Graph workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SKGStage = SKGStage.INGEST_ENTITIES
    config: dict[str, Any] = Field(default_factory=dict)

    entities: list[dict[str, Any]] = Field(default_factory=list)
    relationships: list[dict[str, Any]] = Field(default_factory=list)
    patterns: list[dict[str, Any]] = Field(default_factory=list)
    matches: list[dict[str, Any]] = Field(default_factory=list)
    anomalies: list[dict[str, Any]] = Field(default_factory=list)

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
