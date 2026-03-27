"""State models for the Chaos Engineering Agent."""

from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class ChaosStage(StrEnum):
    """Stages of a chaos engineering experiment."""

    PLAN_EXPERIMENT = "plan_experiment"
    VALIDATE_SAFETY = "validate_safety"
    INJECT_FAULT = "inject_fault"
    OBSERVE_IMPACT = "observe_impact"
    ANALYZE_RESULTS = "analyze_results"
    REPORT = "report"


class FaultType(StrEnum):
    """Supported fault injection types."""

    POD_KILL = "pod_kill"
    NETWORK_LATENCY = "network_latency"
    CPU_STRESS = "cpu_stress"
    MEMORY_PRESSURE = "memory_pressure"
    DISK_FILL = "disk_fill"
    DNS_FAILURE = "dns_failure"


class ExperimentStatus(StrEnum):
    """Status of a chaos experiment."""

    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"
    ROLLED_BACK = "rolled_back"


class ChaosExperiment(BaseModel):
    """Definition of a chaos experiment."""

    id: str = Field(default_factory=lambda: f"chaos-{uuid4().hex[:12]}")
    name: str
    fault_type: FaultType
    target_service: str
    target_namespace: str
    duration_sec: int = 60
    blast_radius: str = "single_pod"
    hypothesis: str = ""
    status: ExperimentStatus = ExperimentStatus.PLANNED


class SafetyCheck(BaseModel):
    """Result of a pre-injection safety check."""

    id: str = Field(default_factory=lambda: f"safety-{uuid4().hex[:12]}")
    experiment_id: str
    check_name: str
    passed: bool
    details: str
    blocking: bool = True


class FaultInjection(BaseModel):
    """Record of an injected fault."""

    id: str = Field(default_factory=lambda: f"fault-{uuid4().hex[:12]}")
    experiment_id: str
    fault_type: FaultType
    target: str
    started_at: float = 0.0
    ended_at: float = 0.0
    rollback_triggered: bool = False


class ImpactObservation(BaseModel):
    """Observation of a metric during fault injection."""

    id: str = Field(default_factory=lambda: f"obs-{uuid4().hex[:12]}")
    experiment_id: str
    metric_name: str
    baseline_value: float
    during_fault_value: float
    deviation_pct: float = 0.0
    recovered: bool = True
    recovery_time_sec: float = 0.0


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class ChaosEngineeringState(BaseModel):
    """Full state of a chaos engineering workflow (LangGraph state)."""

    # Input
    tenant_id: str = ""
    experiment_name: str = ""
    target_service: str = ""
    target_namespace: str = "default"

    # Experiment definition
    experiment: ChaosExperiment | None = None

    # Safety
    safety_checks: list[SafetyCheck] = Field(default_factory=list)
    safety_passed: bool = False

    # Injection
    fault_injection: FaultInjection | None = None

    # Impact
    observations: list[ImpactObservation] = Field(default_factory=list)
    slo_breached: bool = False

    # Analysis
    hypothesis_validated: bool | None = None
    resilience_score: float = 0.0
    recommendations: list[str] = Field(default_factory=list)

    # Report
    report_summary: str = ""

    # Metadata
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_stage: str = "init"
    error: str = ""
    duration_ms: int = 0
