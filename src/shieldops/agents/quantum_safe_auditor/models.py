"""State models for the Quantum Safe Auditor Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class QSAStage(StrEnum):
    """Workflow stages for quantum-safe auditing."""

    INVENTORY_CRYPTO = "inventory_crypto"
    ASSESS_QUANTUM_RISK = "assess_quantum_risk"
    IDENTIFY_VULNERABLE = "identify_vulnerable"
    PLAN_MIGRATION = "plan_migration"
    TRACK_PROGRESS = "track_progress"
    REPORT = "report"


class AlgorithmStatus(StrEnum):
    """Post-quantum readiness status for algorithms."""

    QUANTUM_SAFE = "quantum_safe"
    HYBRID = "hybrid"
    VULNERABLE = "vulnerable"
    DEPRECATED = "deprecated"
    UNKNOWN = "unknown"


class CryptoUsage(StrEnum):
    """Types of cryptographic usage in the organization."""

    TLS = "tls"
    SIGNING = "signing"
    ENCRYPTION = "encryption"
    KEY_EXCHANGE = "key_exchange"
    HASHING = "hashing"
    AUTHENTICATION = "authentication"


# ── Domain Models ─────────────────────────────────────


class CryptoAsset(BaseModel):
    """A cryptographic asset discovered during inventory."""

    asset_id: str = ""
    algorithm: str = ""
    key_size: int = 0
    usage: CryptoUsage = CryptoUsage.TLS
    status: AlgorithmStatus = AlgorithmStatus.UNKNOWN
    service: str = ""
    location: str = ""
    expiry: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class QuantumRisk(BaseModel):
    """Quantum risk assessment for a crypto asset."""

    asset_id: str = ""
    risk_score: float = 0.0
    harvest_now_decrypt_later: bool = False
    time_to_quantum_threat: str = "unknown"
    data_sensitivity: str = "medium"
    reasoning: str = ""


class VulnerableAsset(BaseModel):
    """A crypto asset identified as quantum-vulnerable."""

    asset_id: str = ""
    algorithm: str = ""
    vulnerability: str = ""
    impact: str = "medium"
    recommended_replacement: str = ""
    urgency: str = "medium"


class MigrationPlan(BaseModel):
    """Migration plan for a vulnerable crypto asset."""

    plan_id: str = ""
    asset_id: str = ""
    target_algorithm: str = ""
    effort: str = "medium"
    phases: list[str] = Field(default_factory=list)
    estimated_weeks: int = 0
    dependencies: list[str] = Field(default_factory=list)


class MigrationProgress(BaseModel):
    """Progress tracking for crypto migration."""

    plan_id: str = ""
    status: str = "pending"
    percent_complete: float = 0.0
    blockers: list[str] = Field(default_factory=list)
    last_updated: datetime | None = None


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the QSA workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class QuantumSafeAuditorState(BaseModel):
    """Full state for the Quantum Safe Auditor workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: QSAStage = QSAStage.INVENTORY_CRYPTO
    audit_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Inventory
    crypto_inventory: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_crypto_assets: int = 0

    # Risk
    quantum_risks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    high_risk_count: int = 0

    # Vulnerable
    vulnerable_assets: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    vulnerable_count: int = 0

    # Migration
    migration_plans: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Progress
    migration_progress: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
