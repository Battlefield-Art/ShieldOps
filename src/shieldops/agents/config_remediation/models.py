"""State models for the Config Remediation Agent."""

from __future__ import annotations

from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class RemediationStage(StrEnum):
    """Stages of config remediation workflow."""

    SCAN_CONFIGURATIONS = "scan_configurations"
    IDENTIFY_MISCONFIGS = "identify_misconfigs"
    GENERATE_FIXES = "generate_fixes"
    APPLY_FIXES = "apply_fixes"
    VERIFY_FIXES = "verify_fixes"
    REPORT = "report"


class MisconfigType(StrEnum):
    """Types of security misconfigurations."""

    OVERPERMISSIVE_SG = "overpermissive_sg"
    PUBLIC_STORAGE = "public_storage"
    MISSING_ENCRYPTION = "missing_encryption"
    WEAK_IAM = "weak_iam"
    MISSING_LOGGING = "missing_logging"
    INSECURE_TLS = "insecure_tls"


class FixStatus(StrEnum):
    """Status of a configuration fix."""

    PLANNED = "planned"
    APPROVED = "approved"
    APPLIED = "applied"
    VERIFIED = "verified"
    FAILED = "failed"


class ConfigScan(BaseModel):
    """Result of scanning a configuration source."""

    id: str = Field(default_factory=lambda: f"scan-{uuid4().hex[:12]}")
    resource_type: str
    resource_id: str
    cloud_provider: str = ""
    region: str = ""
    config_snapshot: dict[str, object] = Field(default_factory=dict)


class Misconfiguration(BaseModel):
    """A detected security misconfiguration."""

    id: str = Field(default_factory=lambda: f"misc-{uuid4().hex[:12]}")
    scan_id: str
    misconfig_type: MisconfigType
    resource_id: str
    severity: str = "high"
    description: str = ""
    benchmark_ref: str = ""
    current_value: str = ""
    expected_value: str = ""


class FixPlan(BaseModel):
    """Plan to fix a misconfiguration."""

    id: str = Field(default_factory=lambda: f"fix-{uuid4().hex[:12]}")
    misconfig_id: str
    resource_id: str
    fix_type: str = ""
    fix_description: str = ""
    iac_patch: str = ""
    api_call: str = ""
    dry_run: bool = True
    status: FixStatus = FixStatus.PLANNED
    rollback_command: str = ""


class FixApplication(BaseModel):
    """Record of applying a fix."""

    id: str = Field(default_factory=lambda: f"app-{uuid4().hex[:12]}")
    fix_id: str
    resource_id: str
    applied_at: float = 0.0
    success: bool = False
    error_message: str = ""
    change_id: str = ""


class FixVerification(BaseModel):
    """Result of verifying a fix was applied correctly."""

    id: str = Field(default_factory=lambda: f"fvr-{uuid4().hex[:12]}")
    fix_id: str
    resource_id: str
    still_misconfigured: bool = False
    new_value: str = ""
    verified: bool = False
    details: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class ConfigRemediationState(BaseModel):
    """Full state of the config remediation workflow."""

    # Input
    tenant_id: str = ""
    request_id: str = Field(default_factory=lambda: f"req-{uuid4().hex[:12]}")
    target_cloud: str = "aws"
    dry_run: bool = True

    # Pipeline
    configs_scanned: list[ConfigScan] = Field(default_factory=list)
    misconfigs_found: list[Misconfiguration] = Field(default_factory=list)
    fixes_planned: list[FixPlan] = Field(default_factory=list)
    fixes_applied: list[FixApplication] = Field(default_factory=list)
    fixes_verified: list[FixVerification] = Field(default_factory=list)

    # Counters
    auto_fixed_count: int = 0
    manual_required: int = 0

    # Report
    report_summary: str = ""

    # Metadata
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_stage: str = "init"
    error: str = ""
    duration_ms: int = 0
