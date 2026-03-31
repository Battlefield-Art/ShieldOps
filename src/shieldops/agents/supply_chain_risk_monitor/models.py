"""State models for the Supply Chain Risk Monitor Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SCRMStage(StrEnum):
    """Stages in the supply chain risk monitoring lifecycle."""

    SCAN_SUPPLY_CHAIN = "scan_supply_chain"
    ANALYZE_DEPENDENCIES = "analyze_dependencies"
    DETECT_RISKS = "detect_risks"
    ASSESS_IMPACT = "assess_impact"
    MITIGATE = "mitigate"
    REPORT = "report"


class RiskCategory(StrEnum):
    """Categories of supply chain risk."""

    TYPOSQUATTING = "typosquatting"
    MAINTAINER_RISK = "maintainer_risk"
    BUILD_PROVENANCE = "build_provenance"
    LICENSE_VIOLATION = "license_violation"
    KNOWN_VULNERABILITY = "known_vulnerability"
    DEPENDENCY_CONFUSION = "dependency_confusion"


class SLSALevel(StrEnum):
    """SLSA compliance levels."""

    LEVEL_0 = "level_0"
    LEVEL_1 = "level_1"
    LEVEL_2 = "level_2"
    LEVEL_3 = "level_3"
    LEVEL_4 = "level_4"
    UNKNOWN = "unknown"


# --- Domain models ---


class DependencyRecord(BaseModel):
    """A software dependency in the supply chain."""

    package_name: str = ""
    version: str = ""
    ecosystem: str = ""
    direct: bool = True
    license_type: str = ""
    maintainer_count: int = 0
    last_publish: datetime | None = None
    download_count: int = 0


class SupplyChainRisk(BaseModel):
    """An identified supply chain risk."""

    risk_id: str = ""
    package_name: str = ""
    category: RiskCategory = RiskCategory.KNOWN_VULNERABILITY
    severity: str = "medium"
    confidence: float = 0.0
    description: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)


class ImpactAssessment(BaseModel):
    """Impact assessment for a supply chain risk."""

    risk_id: str = ""
    blast_radius: int = 0
    affected_services: list[str] = Field(default_factory=list)
    exploitability: float = 0.0
    business_impact: str = "low"
    slsa_level: SLSALevel = SLSALevel.UNKNOWN
    remediation_effort: str = "low"


class MitigationAction(BaseModel):
    """A mitigation action for a supply chain risk."""

    action_id: str = ""
    risk_id: str = ""
    action_type: str = ""
    description: str = ""
    automated: bool = False
    applied: bool = False
    new_version: str = ""


class ProvenanceRecord(BaseModel):
    """Build provenance record for SLSA compliance."""

    package_name: str = ""
    version: str = ""
    builder: str = ""
    source_repo: str = ""
    build_trigger: str = ""
    slsa_level: SLSALevel = SLSALevel.UNKNOWN
    signature_valid: bool = False


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the orchestrator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SupplyChainRiskMonitorState(BaseModel):
    """Full state for a supply chain risk monitor run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SCRMStage = SCRMStage.SCAN_SUPPLY_CHAIN

    # Inputs
    scan_target: str = ""
    ecosystems: list[str] = Field(default_factory=list)
    slsa_required_level: SLSALevel = SLSALevel.LEVEL_2
    include_transitive: bool = True

    # Pipeline fields
    dependencies: list[dict[str, Any]] = Field(default_factory=list)
    analyses: list[dict[str, Any]] = Field(default_factory=list)
    risks: list[dict[str, Any]] = Field(default_factory=list)
    assessments: list[dict[str, Any]] = Field(default_factory=list)
    mitigations: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_dependencies: int = 0
    risks_detected: int = 0
    critical_risks: int = 0
    mitigations_applied: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
