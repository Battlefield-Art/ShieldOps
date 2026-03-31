"""State models for the Data Privacy Scanner Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class DPSStage(StrEnum):
    """Stages in the data privacy scanning lifecycle."""

    SCAN_DATASTORES = "scan_datastores"
    CLASSIFY_DATA = "classify_data"
    DETECT_PII = "detect_pii"
    MAP_FLOWS = "map_flows"
    ASSESS_COMPLIANCE = "assess_compliance"
    REPORT = "report"


class DataCategory(StrEnum):
    """Data sensitivity categories."""

    PII = "pii"
    PHI = "phi"
    PCI = "pci"
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"


class ComplianceRegime(StrEnum):
    """Privacy compliance regimes."""

    GDPR = "gdpr"
    CCPA = "ccpa"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOX = "sox"
    FERPA = "ferpa"


# --- Domain models ---


class DatastoreRecord(BaseModel):
    """A discovered datastore or data asset."""

    datastore_id: str = ""
    name: str = ""
    store_type: str = ""
    provider: str = ""
    region: str = ""
    record_count: int = 0
    size_bytes: int = 0
    encrypted: bool = False
    discovered_at: datetime | None = None


class DataClassification(BaseModel):
    """Classification result for a data field or column."""

    datastore_id: str = ""
    field_name: str = ""
    category: DataCategory = DataCategory.INTERNAL
    confidence: float = 0.0
    sample_count: int = 0
    patterns_matched: list[str] = Field(
        default_factory=list,
    )


class PIIFinding(BaseModel):
    """A PII/PHI/PCI finding in a datastore."""

    finding_id: str = ""
    datastore_id: str = ""
    field_name: str = ""
    data_type: str = ""
    category: DataCategory = DataCategory.PII
    record_count: int = 0
    masked: bool = False
    encrypted: bool = False
    severity: str = "medium"


class DataFlowMapping(BaseModel):
    """Mapping of data flows between systems."""

    flow_id: str = ""
    source: str = ""
    destination: str = ""
    data_categories: list[DataCategory] = Field(
        default_factory=list,
    )
    encrypted_in_transit: bool = False
    cross_border: bool = False
    retention_days: int = 0


class ComplianceAssessment(BaseModel):
    """Compliance assessment against a privacy regime."""

    regime: ComplianceRegime = ComplianceRegime.GDPR
    compliant: bool = False
    findings_count: int = 0
    gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(
        default_factory=list,
    )
    score: float = 0.0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the scanner workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class DataPrivacyScannerState(BaseModel):
    """Full state for a data privacy scanner run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: DPSStage = DPSStage.SCAN_DATASTORES

    # Inputs
    scan_name: str = ""
    target_datastores: list[str] = Field(
        default_factory=list,
    )
    scope: dict[str, Any] = Field(default_factory=dict)
    regimes: list[ComplianceRegime] = Field(
        default_factory=list,
    )

    # Pipeline fields
    datastores: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    pii_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    data_flows: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    compliance_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_datastores: int = 0
    pii_count: int = 0
    phi_count: int = 0
    pci_count: int = 0
    compliance_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
