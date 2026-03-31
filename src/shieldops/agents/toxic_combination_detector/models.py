"""State models for the Toxic Combination Detector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class TCDStage(StrEnum):
    """Stages in the toxic combination detection lifecycle."""

    COLLECT_PERMISSIONS = "collect_permissions"
    ANALYZE_COMBINATIONS = "analyze_combinations"
    DETECT_TOXIC = "detect_toxic"
    ASSESS_BLAST_RADIUS = "assess_blast_radius"
    RECOMMEND = "recommend"
    REPORT = "report"


class PermissionScope(StrEnum):
    """Cloud permission scope categories."""

    IAM = "iam"
    STORAGE = "storage"
    COMPUTE = "compute"
    NETWORK = "network"
    DATABASE = "database"
    SERVERLESS = "serverless"


class ViolationType(StrEnum):
    """Types of toxic combination violations."""

    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    SOD_VIOLATION = "sod_violation"
    BLAST_RADIUS = "blast_radius"
    SUPPLY_CHAIN = "supply_chain"


# --- Domain models ---


class PermissionSet(BaseModel):
    """A set of permissions for an identity."""

    identity_id: str = ""
    identity_type: str = "user"
    provider: str = "aws"
    permissions: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    scope: PermissionScope = PermissionScope.IAM
    last_used: datetime | None = None


class PermissionCombination(BaseModel):
    """An analyzed combination of permissions."""

    combo_id: str = ""
    identity_id: str = ""
    permissions: list[str] = Field(default_factory=list)
    is_toxic: bool = False
    violation_type: ViolationType = ViolationType.PRIVILEGE_ESCALATION
    risk_score: float = 0.0
    description: str = ""


class ToxicCombo(BaseModel):
    """A detected toxic permission combination."""

    toxic_id: str = ""
    identity_id: str = ""
    permissions: list[str] = Field(default_factory=list)
    violation_type: ViolationType = ViolationType.PRIVILEGE_ESCALATION
    severity: str = "high"
    attack_chain: list[str] = Field(default_factory=list)
    example_scenario: str = ""


class BlastRadiusAssessment(BaseModel):
    """Blast radius assessment for a toxic combination."""

    assessment_id: str = ""
    toxic_id: str = ""
    affected_resources: list[str] = Field(default_factory=list)
    affected_identities: list[str] = Field(default_factory=list)
    data_at_risk: list[str] = Field(default_factory=list)
    blast_radius_score: float = 0.0
    containment_difficulty: str = "medium"


class RemediationRecommendation(BaseModel):
    """Remediation recommendation for a toxic combo."""

    recommendation_id: str = ""
    toxic_id: str = ""
    action: str = ""
    priority: int = 0
    effort: str = "medium"
    permissions_to_revoke: list[str] = Field(default_factory=list)
    alternative_roles: list[str] = Field(default_factory=list)
    sod_policy: str = ""


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the detector workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ToxicCombinationDetectorState(BaseModel):
    """Full state for a toxic combination detector run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: TCDStage = TCDStage.COLLECT_PERMISSIONS

    # Inputs
    scan_name: str = ""
    target_providers: list[str] = Field(
        default_factory=list,
    )
    target_identities: list[str] = Field(
        default_factory=list,
    )
    sod_policies: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Pipeline fields
    permissions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    combinations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    toxic_combos: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    blast_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_identities: int = 0
    total_toxic: int = 0
    critical_toxic: int = 0
    max_blast_radius: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
