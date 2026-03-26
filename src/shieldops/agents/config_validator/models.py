"""State models for the Config Validator Agent."""

from enum import StrEnum

from pydantic import BaseModel, Field


class ValidatorStage(StrEnum):
    """Stages of the config validation workflow."""

    COLLECT_CONFIGS = "collect_configs"
    COMPARE_BASELINES = "compare_baselines"
    DETECT_DRIFT = "detect_drift"
    ASSESS_IMPACT = "assess_impact"
    REMEDIATE = "remediate"
    REPORT = "report"


class ConfigSource(StrEnum):
    """Infrastructure config source types."""

    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"
    HELM = "helm"
    DOCKER = "docker"
    APPLICATION = "application"
    CLOUD_IAM = "cloud_iam"


class DriftSeverity(StrEnum):
    """Severity levels for configuration drift."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    COSMETIC = "cosmetic"


class ConfigSnapshot(BaseModel):
    """Point-in-time snapshot of a configuration resource."""

    id: str
    source: ConfigSource
    resource_name: str
    config_hash: str
    last_validated: float
    compliant: bool
    service: str


class ConfigDrift(BaseModel):
    """A detected drift between expected and actual configuration."""

    id: str
    snapshot_id: str
    source: ConfigSource
    field_path: str
    expected_value: str
    actual_value: str
    severity: DriftSeverity
    auto_fixable: bool
    introduced_at: float


class ImpactAssessment(BaseModel):
    """Impact assessment for a detected configuration drift."""

    id: str
    drift_id: str
    affected_services: list[str] = Field(default_factory=list)
    security_impact: str
    availability_impact: str
    compliance_impact: str


class RemediationAction(BaseModel):
    """A remediation action taken to fix configuration drift."""

    id: str
    drift_id: str
    action: str
    description: str
    applied: bool = False
    success: bool = False
    rollback_available: bool = True


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class ConfigValidatorState(BaseModel):
    """Full state of a config validation workflow (LangGraph state)."""

    # Input
    tenant_id: str
    run_id: str = ""

    # Collected data
    snapshots: list[ConfigSnapshot] = Field(default_factory=list)
    drifts: list[ConfigDrift] = Field(default_factory=list)
    impact_assessments: list[ImpactAssessment] = Field(default_factory=list)
    remediations: list[RemediationAction] = Field(default_factory=list)

    # Output
    report_summary: str = ""
    total_configs: int = 0
    compliant_count: int = 0
    drift_count: int = 0

    # Metadata
    stage: ValidatorStage = ValidatorStage.COLLECT_CONFIGS
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    started_at: float = 0.0
    duration_ms: int = 0
    error: str | None = None
