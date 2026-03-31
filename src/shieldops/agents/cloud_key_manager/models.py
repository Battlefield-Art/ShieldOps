"""Cloud Key Manager Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CKMStage(StrEnum):
    DISCOVER_KEYS = "discover_keys"
    AUDIT_ROTATION = "audit_rotation"
    CHECK_USAGE = "check_usage"
    ASSESS_RISK = "assess_risk"
    ENFORCE_POLICY = "enforce_policy"
    REPORT = "report"


class KeyProvider(StrEnum):
    AWS_KMS = "aws_kms"
    GCP_KMS = "gcp_kms"
    AZURE_KEY_VAULT = "azure_key_vault"
    HASHICORP_VAULT = "hashicorp_vault"
    ON_PREMISE_HSM = "on_premise_hsm"
    CUSTOM = "custom"


class KeyRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    COMPLIANT = "compliant"


class CloudKey(BaseModel):
    """A single cloud KMS key entry."""

    id: str = ""
    provider: KeyProvider = KeyProvider.AWS_KMS
    key_id: str = ""
    alias: str = ""
    algorithm: str = "AES-256"
    state: str = "enabled"
    created_at: str = ""
    last_rotated: str = ""
    rotation_days: int = 0
    region: str = ""
    usage_count: int = 0


class RotationAudit(BaseModel):
    """Rotation audit result for a key."""

    id: str = ""
    key_id: str = ""
    provider: KeyProvider = KeyProvider.AWS_KMS
    last_rotation: str = ""
    days_since_rotation: int = 0
    policy_max_days: int = 90
    compliant: bool = True
    auto_rotate_enabled: bool = False
    recommendation: str = ""


class KeyUsage(BaseModel):
    """Usage analysis for a key."""

    id: str = ""
    key_id: str = ""
    encrypt_ops: int = 0
    decrypt_ops: int = 0
    sign_ops: int = 0
    total_ops_30d: int = 0
    last_used: str = ""
    unused_days: int = 0
    services: list[str] = Field(default_factory=list)


class KeyRiskAssessment(BaseModel):
    """Risk assessment for a key."""

    id: str = ""
    key_id: str = ""
    risk: KeyRisk = KeyRisk.LOW
    findings: list[str] = Field(default_factory=list)
    crypto_agility_score: float = 0.0
    quantum_safe: bool = False
    cross_region_backup: bool = False


class PolicyEnforcement(BaseModel):
    """Result of key policy enforcement."""

    id: str = ""
    key_id: str = ""
    action: str = ""
    status: str = ""
    rotation_scheduled: bool = False
    policy_applied: str = ""
    rollback_available: bool = True


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudKeyManagerState(BaseModel):
    """Main state for the Cloud Key Manager agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CKMStage = CKMStage.DISCOVER_KEYS

    keys: list[CloudKey] = Field(default_factory=list)
    rotation_audits: list[RotationAudit] = Field(default_factory=list)
    usages: list[KeyUsage] = Field(default_factory=list)
    risk_assessments: list[KeyRiskAssessment] = Field(default_factory=list)
    enforcements: list[PolicyEnforcement] = Field(default_factory=list)

    report: str = ""
    total_keys_discovered: int = 0
    keys_at_risk: int = 0

    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
