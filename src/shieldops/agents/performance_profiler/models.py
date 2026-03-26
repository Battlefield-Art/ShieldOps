"""Performance Profiler Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ProfilerStage(StrEnum):
    COLLECT_TRACES = "collect_traces"
    ANALYZE_LATENCY = "analyze_latency"
    DETECT_BOTTLENECKS = "detect_bottlenecks"
    IDENTIFY_CONTENTION = "identify_contention"
    RECOMMEND = "recommend"
    REPORT = "report"


class BottleneckType(StrEnum):
    DATABASE_QUERY = "database_query"
    EXTERNAL_API = "external_api"
    CPU_BOUND = "cpu_bound"
    MEMORY_ALLOCATION = "memory_allocation"
    LOCK_CONTENTION = "lock_contention"
    NETWORK_IO = "network_io"


class ImpactLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class TraceSpan(BaseModel):
    """A single span from a distributed trace."""

    id: str = ""
    service: str = ""
    operation: str = ""
    duration_ms: float = Field(default=0.0, ge=0.0)
    parent_id: str = ""
    status_code: int = 200
    tags: dict[str, Any] = Field(default_factory=dict)


class LatencyAnalysis(BaseModel):
    """Latency distribution analysis for a service endpoint."""

    id: str = ""
    service: str = ""
    endpoint: str = ""
    p50_ms: float = Field(default=0.0, ge=0.0)
    p95_ms: float = Field(default=0.0, ge=0.0)
    p99_ms: float = Field(default=0.0, ge=0.0)
    error_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    requests_per_sec: float = Field(default=0.0, ge=0.0)


class PerformanceBottleneck(BaseModel):
    """A detected performance bottleneck with optimization guidance."""

    id: str = ""
    service: str = ""
    bottleneck_type: BottleneckType = BottleneckType.DATABASE_QUERY
    description: str = ""
    impact: ImpactLevel = ImpactLevel.MEDIUM
    avg_latency_ms: float = Field(default=0.0, ge=0.0)
    optimization: str = ""
    estimated_improvement_pct: float = Field(default=0.0, ge=0.0, le=100.0)


class ResourceContention(BaseModel):
    """Resource contention detected in a service."""

    id: str = ""
    service: str = ""
    resource: str = ""
    contention_type: str = ""
    severity: str = ""
    affected_operations: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class PerformanceProfilerState(BaseModel):
    """Main state for the Performance Profiler agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: ProfilerStage = ProfilerStage.COLLECT_TRACES

    # Collected trace spans
    spans: list[TraceSpan] = Field(default_factory=list)

    # Latency analysis results
    latency_analyses: list[LatencyAnalysis] = Field(default_factory=list)

    # Detected bottlenecks
    bottlenecks: list[PerformanceBottleneck] = Field(default_factory=list)

    # Resource contention findings
    contentions: list[ResourceContention] = Field(default_factory=list)

    # Optimization recommendations
    recommendations: list[str] = Field(default_factory=list)

    # Summary report
    report: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
