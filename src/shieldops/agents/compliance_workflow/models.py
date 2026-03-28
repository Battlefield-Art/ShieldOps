"""State models for Compliance Workflow Agent."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ComplianceStage(StrEnum):
    """Stages in the compliance audit workflow."""

    IDENTIFY_CONTROLS = "identify_controls"
    COLLECT_EVIDENCE = "collect_evidence"
    TEST_CONTROLS = "test_controls"
    IDENTIFY_GAPS = "identify_gaps"
    REMEDIATE = "remediate"
    REPORT = "report"


class Framework(StrEnum):
    """Supported compliance frameworks."""

    SOC2 = "soc2"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    ISO27001 = "iso27001"
    NIST_CSF = "nist_csf"


class ControlStatus(StrEnum):
    """Control testing status."""

    PASSING = "passing"
    FAILING = "failing"
    NOT_TESTED = "not_tested"
    PARTIALLY_PASSING = "partially_passing"
    EXEMPT = "exempt"


class ComplianceControl(BaseModel):
    """A single compliance control."""

    id: str = ""
    name: str = ""
    framework: Framework = Framework.SOC2
    category: str = ""
    description: str = ""
    status: ControlStatus = ControlStatus.NOT_TESTED
    owner: str = ""


class EvidenceItem(BaseModel):
    """Evidence collected for a control."""

    id: str = ""
    control_id: str = ""
    source: str = ""
    description: str = ""
    collected_at: float = 0.0
    valid: bool = False


class GapFinding(BaseModel):
    """A gap identified during control testing."""

    id: str = ""
    control_id: str = ""
    severity: str = "medium"
    description: str = ""
    remediation_plan: str = ""
    resolved: bool = False


class ComplianceWorkflowState(BaseModel):
    """Full state for Compliance Workflow Agent."""

    request_id: str = ""
    stage: ComplianceStage = ComplianceStage.IDENTIFY_CONTROLS
    tenant_id: str = ""
    framework: Framework = Framework.SOC2
    controls: list[ComplianceControl] = Field(default_factory=list)
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    gaps: list[GapFinding] = Field(default_factory=list)
    remediation_items: list[dict[str, str]] = Field(
        default_factory=list,
    )
    overall_score: float = 0.0
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_start: float = 0.0
