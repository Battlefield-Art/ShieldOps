"""State models for the Air-Gap Vault Agent."""

from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class VaultStage(StrEnum):
    """Stages of the air-gap vault verification workflow."""

    INVENTORY_VAULT_ASSETS = "inventory_vault_assets"
    VERIFY_ISOLATION = "verify_isolation"
    CHECK_INTEGRITY = "check_integrity"
    DETECT_TAMPERING = "detect_tampering"
    ENFORCE_RETENTION = "enforce_retention"
    REPORT = "report"


class IsolationLevel(StrEnum):
    """Isolation level of a vault asset."""

    FULL_AIR_GAP = "full_air_gap"
    LOGICAL_AIR_GAP = "logical_air_gap"
    NETWORK_ISOLATED = "network_isolated"
    STANDARD = "standard"


class IntegrityStatus(StrEnum):
    """Integrity verification status of a vault asset."""

    VERIFIED = "verified"
    DEGRADED = "degraded"
    TAMPERED = "tampered"
    UNKNOWN = "unknown"


class VaultAsset(BaseModel):
    """An asset stored in the air-gapped vault."""

    id: str = Field(default_factory=lambda: f"vasset-{uuid4().hex[:12]}")
    name: str
    asset_type: str  # model_weights, rag_index, training_data, backup
    size_bytes: int = 0
    isolation_level: IsolationLevel = IsolationLevel.STANDARD
    integrity_status: IntegrityStatus = IntegrityStatus.UNKNOWN
    hash_chain: list[str] = Field(default_factory=list)
    last_verified_at: float = 0.0
    storage_location: str = ""
    tenant_id: str = ""


class IsolationVerification(BaseModel):
    """Result of an isolation verification check."""

    id: str = Field(default_factory=lambda: f"iso-{uuid4().hex[:12]}")
    asset_id: str
    isolation_level: IsolationLevel
    network_reachable: bool = False
    dns_resolvable: bool = False
    egress_blocked: bool = True
    ingress_restricted: bool = True
    passed: bool = True
    details: str = ""


class IntegrityCheck(BaseModel):
    """Result of a cryptographic integrity check."""

    id: str = Field(default_factory=lambda: f"integ-{uuid4().hex[:12]}")
    asset_id: str
    expected_hash: str = ""
    actual_hash: str = ""
    hash_algorithm: str = "sha256"
    chain_valid: bool = True
    status: IntegrityStatus = IntegrityStatus.UNKNOWN
    details: str = ""


class TamperDetection(BaseModel):
    """A tamper detection alert."""

    id: str = Field(default_factory=lambda: f"tamper-{uuid4().hex[:12]}")
    asset_id: str
    alert_type: str  # unexpected_access, modification, deletion_attempt
    severity: str = "medium"  # low, medium, high, critical
    source_ip: str = ""
    timestamp: float = 0.0
    details: str = ""
    mitigated: bool = False


class RetentionPolicy(BaseModel):
    """A retention policy applied to vault assets."""

    id: str = Field(default_factory=lambda: f"ret-{uuid4().hex[:12]}")
    asset_id: str
    policy_name: str
    retention_days: int = 365
    legal_hold: bool = False
    compliance_framework: str = ""  # SOC2, HIPAA, PCI, GDPR
    enforced: bool = True
    expires_at: float = 0.0
    details: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class AirGapVaultState(BaseModel):
    """Full state of an air-gap vault workflow (LangGraph state)."""

    # Input
    tenant_id: str = ""
    vault_id: str = ""
    scan_scope: str = "all"  # all, ai_assets, backups

    # Inventory
    vault_assets: list[VaultAsset] = Field(default_factory=list)

    # Isolation
    isolation_checks: list[IsolationVerification] = Field(default_factory=list)
    isolation_passed: bool = False

    # Integrity
    integrity_verifications: list[IntegrityCheck] = Field(default_factory=list)

    # Tampering
    tamper_alerts: list[TamperDetection] = Field(default_factory=list)

    # Retention
    retention_policies: list[RetentionPolicy] = Field(default_factory=list)

    # Scoring
    vault_health_score: float = 0.0
    recommendations: list[str] = Field(default_factory=list)

    # Report
    report_summary: str = ""

    # Metadata
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_stage: str = "init"
    error: str = ""
    duration_ms: int = 0
