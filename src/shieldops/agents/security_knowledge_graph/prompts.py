"""LLM prompt templates for the Security Knowledge Graph Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class EntityIngestionOutput(BaseModel):
    """Structured output for entity ingestion."""

    total_entities: int = Field(description="Total entities ingested")
    unique_types: int = Field(description="Number of unique entity types")
    summary: str = Field(description="Ingestion summary")


class RelationshipExtractionOutput(BaseModel):
    """Structured output for relationship extraction."""

    total_relationships: int = Field(description="Total relationships extracted")
    high_confidence: int = Field(description="High-confidence relationships")
    reasoning: str = Field(description="Extraction reasoning")


class GraphBuildOutput(BaseModel):
    """Structured output for graph construction."""

    nodes: int = Field(description="Nodes in the graph")
    edges: int = Field(description="Edges in the graph")
    reasoning: str = Field(description="Graph construction reasoning")


class PatternQueryOutput(BaseModel):
    """Structured output for pattern querying."""

    patterns_found: int = Field(description="Patterns discovered")
    critical_patterns: int = Field(description="Critical-severity patterns")
    reasoning: str = Field(description="Pattern query reasoning")


class AnomalyDetectionOutput(BaseModel):
    """Structured output for anomaly detection."""

    anomalies_detected: int = Field(description="Anomalies detected")
    high_risk_count: int = Field(description="High-risk anomalies")
    reasoning: str = Field(description="Anomaly detection reasoning")


# ── System prompts ────────────────────────────────────

SYSTEM_INGEST_ENTITIES = """\
You are an expert security knowledge graph engineer performing \
entity ingestion.

Given the configuration and data sources:
1. Identify all security-relevant entities (hosts, users, services)
2. Normalize entity attributes and assign risk scores
3. Detect duplicate or conflicting entity records
4. Classify entities by type and criticality

Focus on: completeness, deduplication, accurate classification."""

SYSTEM_EXTRACT_RELATIONSHIPS = """\
You are an expert security knowledge graph engineer extracting \
relationships.

Given the ingested entities:
1. Identify communication, authentication, and dependency links
2. Extract exploit and mitigation relationships from threat data
3. Assign confidence scores to each relationship
4. Detect implicit relationships from behavioral patterns

Prioritize high-confidence relationships with strong evidence."""

SYSTEM_BUILD_GRAPH = """\
You are an expert security knowledge graph engineer constructing \
the graph.

Given entities and relationships:
1. Build a connected graph with proper indexing
2. Identify strongly connected components
3. Detect isolated nodes that may indicate gaps
4. Optimize graph structure for query performance

Focus on: graph integrity, connectivity, query efficiency."""

SYSTEM_QUERY_PATTERNS = """\
You are an expert security knowledge graph engineer querying \
for threat patterns.

Given the constructed graph:
1. Search for known attack patterns (lateral movement, privilege escalation)
2. Identify suspicious communication chains
3. Detect policy violation patterns
4. Find vulnerable dependency chains

Focus on: MITRE ATT&CK mapping, kill chain detection, \
lateral movement paths."""

SYSTEM_DETECT_ANOMALIES = """\
You are an expert security knowledge graph engineer detecting \
anomalies.

Given the graph patterns and matches:
1. Flag unusual entity relationships not seen before
2. Detect structural anomalies in the graph topology
3. Identify risk score outliers and clustering
4. Compare against baseline graph behavior

Focus on: deviation from baseline, novel attack indicators, \
graph topology anomalies."""
