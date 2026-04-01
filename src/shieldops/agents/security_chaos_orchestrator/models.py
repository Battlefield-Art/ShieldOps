"""State models for the Security Chaos Orchestrator Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class SCOStage(StrEnum):
    """Workflow stages for security chaos orchestration."""

    PLAN_EXPERIMENTS = "plan_experiments"
    DEFINE_BLAST_RADIUS = "define_blast_radius"
    INJECT_FAILURES = "inject_failures"
    OBSERVE_BEHAVIOR = "observe_behavior"
    ANALYZE_RESILIENCE = "analyze_resilience"
    REPORT = "report"


class ExperimentType(StrEnum):
    """Types of chaos experiments."""

    NETWORK_PARTITION = "network_partition"
    SERVICE_FAILURE = "service_failure"
    LATENCY_INJECTION = "latency_injection"
    CREDENTIAL_REVOCATION = "credential_revocation"
    RESOURCE_EXHAUSTION = "resource_exhaustion"


class ResilienceLevel(StrEnum):
    """Resilience assessment levels."""

    ROBUST = "robust"
    ADEQUATE = "adequate"
    FRAGILE = "fragile"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


# ── Domain Models ─────────────────────────────────────


class ExperimentPlan(BaseModel):
    """A planned chaos experiment."""

    experiment_id: str = ""
    experiment_type: ExperimentType = ExperimentType.SERVICE_FAILURE
    target_service: str = ""
    description: str = ""
    risk_score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class BlastRadius(BaseModel):
    """Blast radius definition for an experiment."""

    experiment_id: str = ""
    affected_services: list[str] = Field(default_factory=list)
    max_impact_percentage: float = 0.0
    rollback_plan: str = ""
    approved: bool = False


class FailureInjection(BaseModel):
    """A failure injection record."""

    injection_id: str = ""
    experiment_id: str = ""
    target: str = ""
    injection_type: str = ""
    status: str = "pending"
    started_at: str = ""


class BehaviorObservation(BaseModel):
    """Observed behavior during chaos experiment."""

    observation_id: str = ""
    experiment_id: str = ""
    metric: str = ""
    baseline_value: float = 0.0
    observed_value: float = 0.0
    deviation_pct: float = 0.0


class ResilienceAssessment(BaseModel):
    """Resilience analysis result."""

    experiment_id: str = ""
    resilience_level: ResilienceLevel = ResilienceLevel.UNKNOWN
    recovery_time_ms: int = 0
    weaknesses: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the chaos orchestration workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityChaosOrchestratorState(BaseModel):
    """Full state for the Security Chaos Orchestrator workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SCOStage = SCOStage.PLAN_EXPERIMENTS
    config: dict[str, Any] = Field(default_factory=dict)

    experiments: list[dict[str, Any]] = Field(default_factory=list)
    blast_radii: list[dict[str, Any]] = Field(default_factory=list)
    injections: list[dict[str, Any]] = Field(default_factory=list)
    observations: list[dict[str, Any]] = Field(default_factory=list)
    assessments: list[dict[str, Any]] = Field(default_factory=list)

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
