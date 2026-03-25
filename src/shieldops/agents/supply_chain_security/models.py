"""Supply Chain Security Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SupplyChainStage(StrEnum):
    GENERATE_SBOM = "generate_sbom"
    SCAN_DEPENDENCIES = "scan_dependencies"
    AUDIT_CICD = "audit_cicd"
    VERIFY_SIGNATURES = "verify_signatures"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class DependencyRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class PipelineThreat(StrEnum):
    CODE_INJECTION = "code_injection"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    TYPOSQUATTING = "typosquatting"
    COMPROMISED_ACTION = "compromised_action"
    UNSIGNED_ARTIFACT = "unsigned_artifact"
    SECRET_EXPOSURE = "secret_exposure"  # noqa: S105


class SBOMEntry(BaseModel):
    """A single entry in a Software Bill of Materials."""

    id: str = ""
    package_name: str = ""
    version: str = ""
    ecosystem: str = ""  # npm, pip, maven, go
    license: str = ""
    direct: bool = True
    vulnerabilities: int = 0
    risk_level: DependencyRisk = DependencyRisk.SAFE


class DependencyVulnerability(BaseModel):
    """A vulnerability discovered in a dependency."""

    id: str = ""
    package_name: str = ""
    version: str = ""
    cve_id: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    fix_available: bool = False
    fixed_version: str = ""
    exploitable: bool = False


class PipelineFinding(BaseModel):
    """A security finding in a CI/CD pipeline."""

    id: str = ""
    pipeline_name: str = ""
    stage: str = ""
    threat_type: PipelineThreat = PipelineThreat.CODE_INJECTION
    description: str = ""
    severity: str = "medium"
    file_path: str = ""
    remediation: str = ""


class SignatureVerification(BaseModel):
    """Result of an artifact signature verification."""

    id: str = ""
    artifact_name: str = ""
    artifact_type: str = ""
    signed: bool = False
    signer: str = ""
    trust_chain_valid: bool = False
    timestamp: float = 0.0


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SupplyChainSecurityState(BaseModel):
    """Main state for the Supply Chain Security graph."""

    # Input
    request_id: str = ""
    stage: SupplyChainStage = SupplyChainStage.GENERATE_SBOM
    tenant_id: str = ""
    repositories: list[str] = Field(default_factory=list)

    # Analysis results
    sbom_entries: list[dict[str, Any]] = Field(default_factory=list)
    dependency_vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    pipeline_findings: list[dict[str, Any]] = Field(default_factory=list)
    signature_verifications: list[dict[str, Any]] = Field(default_factory=list)

    # Risk
    risk_score: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
