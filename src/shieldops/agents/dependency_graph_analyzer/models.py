"""Dependency Graph Analyzer Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class GraphStage(StrEnum):
    BUILD_GRAPH = "build_graph"
    ANALYZE_DEPTH = "analyze_depth"
    FIND_BOTTLENECKS = "find_bottlenecks"
    DETECT_CYCLES = "detect_cycles"
    SCORE = "score"
    REPORT = "report"


class NodeType(StrEnum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    DEV_ONLY = "dev_only"
    OPTIONAL = "optional"
    PEER = "peer"
    BUNDLED = "bundled"


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    OUTDATED = "outdated"
    VULNERABLE = "vulnerable"
    ABANDONED = "abandoned"
    MALICIOUS = "malicious"


class DependencyGraphAnalyzerState(BaseModel):
    request_id: str = ""
    stage: GraphStage = GraphStage.BUILD_GRAPH
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
