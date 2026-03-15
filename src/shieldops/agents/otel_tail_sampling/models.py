"""OTel Tail Sampling Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class SamplingStage(StrEnum):
    ANALYZE = "analyze"
    DESIGN_POLICY = "design_policy"
    SIMULATE = "simulate"
    APPLY = "apply"


class PolicyType(StrEnum):
    ALWAYS_SAMPLE = "always_sample"
    LATENCY = "latency"
    ERROR = "error"
    STATUS_CODE = "status_code"
    STRING_ATTRIBUTE = "string_attribute"
    RATE_LIMITING = "rate_limiting"
    COMPOSITE = "composite"


class SamplingDecision(StrEnum):
    SAMPLE = "sample"
    DROP = "drop"
    DEFER = "defer"


class SamplingPolicy(BaseModel):
    """A single tail-sampling policy definition."""

    name: str = ""
    policy_type: PolicyType = PolicyType.ALWAYS_SAMPLE
    threshold: float = 0.0
    attribute_key: str = ""
    attribute_values: list[str] = Field(default_factory=list)
    sample_rate: float = 1.0


class TraceProfile(BaseModel):
    """Profile of trace patterns for a service."""

    service: str = ""
    avg_latency_ms: float = 0.0
    error_rate: float = 0.0
    volume_per_min: int = 0
    p99_latency_ms: float = 0.0


class SimulationResult(BaseModel):
    """Result of simulating a sampling policy against trace data."""

    policy_name: str = ""
    traces_sampled: int = 0
    traces_dropped: int = 0
    estimated_cost_reduction: float = 0.0
    coverage_impact: str = ""


class OTelTailSamplingState(BaseModel):
    """Main state for the OTel Tail Sampling agent graph."""

    request_id: str = ""
    stage: SamplingStage = SamplingStage.ANALYZE
    trace_profiles: list[TraceProfile] = Field(default_factory=list)
    policies: list[SamplingPolicy] = Field(default_factory=list)
    simulations: list[SimulationResult] = Field(default_factory=list)
    applied_policies: list[str] = Field(default_factory=list)
    cost_savings_pct: float = 0.0
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
