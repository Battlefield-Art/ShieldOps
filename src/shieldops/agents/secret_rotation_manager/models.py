"""Secret Rotation Manager Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SRMStage(StrEnum):
    INVENTORY_SECRETS = "inventory_secrets"
    ASSESS_ROTATION = "assess_rotation"
    PLAN_ROTATION = "plan_rotation"
    EXECUTE_ROTATION = "execute_rotation"
    VERIFY_HEALTH = "verify_health"
    REPORT = "report"


class SecretType(StrEnum):
    API_KEY = "api_key"
    DATABASE_CREDENTIAL = "database_credential"
    TLS_CERTIFICATE = "tls_certificate"
    SSH_KEY = "ssh_key"
    OAUTH_TOKEN = "oauth_token"
    SERVICE_ACCOUNT = "service_account"


class RotationStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class SecretInventory(BaseModel):
    """A discovered secret across vaults and providers."""

    id: str = ""
    name: str = ""
    secret_type: SecretType = SecretType.API_KEY
    vault: str = ""
    provider: str = ""
    owner: str = ""
    age_days: int = 0
    last_rotated: str = ""
    consumers: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)


class RotationAssessment(BaseModel):
    """Risk assessment for a secret needing rotation."""

    secret_id: str = ""
    secret_name: str = ""
    secret_type: SecretType = SecretType.API_KEY
    risk_score: float = 0.0
    age_days: int = 0
    policy_compliant: bool = True
    rotation_urgency: str = "low"
    consumer_count: int = 0
    blast_radius: str = "low"


class RotationPlan(BaseModel):
    """Plan for rotating a specific secret."""

    id: str = ""
    secret_id: str = ""
    secret_name: str = ""
    strategy: str = ""
    pre_checks: list[str] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    rollback_steps: list[str] = Field(default_factory=list)
    estimated_downtime_seconds: int = 0
    requires_approval: bool = False


class RotationExecution(BaseModel):
    """Result of executing a rotation plan."""

    id: str = ""
    plan_id: str = ""
    secret_id: str = ""
    status: RotationStatus = RotationStatus.PENDING
    started_at: str = ""
    completed_at: str = ""
    new_secret_version: str = ""
    rollback_available: bool = True
    error_message: str = ""


class HealthVerification(BaseModel):
    """Post-rotation health check result."""

    execution_id: str = ""
    secret_id: str = ""
    service_name: str = ""
    healthy: bool = True
    latency_ms: float = 0.0
    error_rate_pct: float = 0.0
    verified_at: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecretRotationManagerState(BaseModel):
    """Main state for the Secret Rotation Manager agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SRMStage = SRMStage.INVENTORY_SECRETS

    inventory: list[SecretInventory] = Field(
        default_factory=list,
    )
    assessments: list[RotationAssessment] = Field(
        default_factory=list,
    )
    rotation_plans: list[RotationPlan] = Field(
        default_factory=list,
    )
    executions: list[RotationExecution] = Field(
        default_factory=list,
    )
    health_checks: list[HealthVerification] = Field(
        default_factory=list,
    )

    report: str = ""
    total_secrets: int = 0
    secrets_rotated: int = 0
    secrets_failed: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
