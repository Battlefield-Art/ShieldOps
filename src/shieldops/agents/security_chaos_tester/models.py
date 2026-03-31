"""State models for the Security Chaos Tester Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SCTStage(StrEnum):
    """Stages in the security chaos testing lifecycle."""

    DEFINE_EXPERIMENT = "define_experiment"
    INJECT_FAULT = "inject_fault"
    OBSERVE_BEHAVIOR = "observe_behavior"
    ASSESS_RESILIENCE = "assess_resilience"
    DOCUMENT_FINDINGS = "document_findings"
    REPORT = "report"


class FaultType(StrEnum):
    """Type of security fault to inject."""

    CREDENTIAL_REVOCATION = "credential_revocation"
    FIREWALL_DISRUPTION = "firewall_disruption"
    KEY_ROTATION_FAILURE = "key_rotation_failure"
    CERTIFICATE_EXPIRY = "certificate_expiry"
    IAM_POLICY_CHANGE = "iam_policy_change"
    NETWORK_ISOLATION = "network_isolation"


class ResilienceRating(StrEnum):
    """Resilience rating for a tested component."""

    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    CRITICAL = "critical"


# --- Domain models ---


class ChaosExperiment(BaseModel):
    """A security chaos experiment definition."""

    experiment_id: str = ""
    name: str = ""
    fault_type: FaultType = FaultType.CREDENTIAL_REVOCATION
    target_component: str = ""
    blast_radius: str = "limited"
    rollback_plan: str = ""
    expected_behavior: str = ""
    timeout_seconds: int = 300


class FaultInjection(BaseModel):
    """Record of an injected security fault."""

    injection_id: str = ""
    experiment_id: str = ""
    fault_type: FaultType = FaultType.CREDENTIAL_REVOCATION
    target: str = ""
    injected_at: datetime | None = None
    rolled_back: bool = False
    rollback_at: datetime | None = None


class BehaviorObservation(BaseModel):
    """Observation during fault injection."""

    observation_id: str = ""
    component: str = ""
    expected: str = ""
    actual: str = ""
    deviation_score: float = 0.0
    alerts_triggered: int = 0
    recovery_time_ms: int = 0


class ResilienceScore(BaseModel):
    """Resilience score for a tested component."""

    component: str = ""
    rating: ResilienceRating = ResilienceRating.FAIR
    detection_time_ms: int = 0
    recovery_time_ms: int = 0
    alert_accuracy: float = 0.0
    failover_success: bool = False
    score: float = 0.0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the chaos testing workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityChaosState(BaseModel):
    """Full state for a security chaos tester run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SCTStage = SCTStage.DEFINE_EXPERIMENT

    # Inputs
    experiment_name: str = ""
    fault_types: list[FaultType] = Field(
        default_factory=list,
    )
    target_components: list[str] = Field(
        default_factory=list,
    )
    scope: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    experiments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    injections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    observations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    resilience_scores: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_experiments: int = 0
    total_faults_injected: int = 0
    avg_resilience_score: float = 0.0
    critical_failures: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
