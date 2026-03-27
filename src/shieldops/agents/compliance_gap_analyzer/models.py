"""Compliance Gap Analyzer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ComplianceStage(StrEnum):
    """Stages of the compliance gap analysis pipeline."""

    INVENTORY_CONTROLS = "inventory_controls"
    MAP_TO_FRAMEWORKS = "map_to_frameworks"
    ASSESS_COVERAGE = "assess_coverage"
    IDENTIFY_GAPS = "identify_gaps"
    GENERATE_REMEDIATION_PLAN = "generate_remediation_plan"
    REPORT = "report"


class Framework(StrEnum):
    """Compliance frameworks."""

    SOC2 = "soc2"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    NIST_CSF = "nist_csf"
    ISO27001 = "iso27001"
    CIS_BENCHMARK = "cis_benchmark"
    FEDRAMP = "fedramp"


class ControlStatus(StrEnum):
    """Implementation status of a control."""

    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    MISSING = "missing"
    NOT_APPLICABLE = "not_applicable"


class SecurityControl(BaseModel):
    """A security control in the organization."""

    id: str = ""
    name: str = ""
    description: str = ""
    category: str = ""
    status: ControlStatus = ControlStatus.MISSING
    owner: str = ""
    evidence: list[str] = Field(
        default_factory=list,
    )


class FrameworkMapping(BaseModel):
    """Mapping between a control and a framework req."""

    control_id: str = ""
    framework: Framework = Framework.SOC2
    requirement_id: str = ""
    requirement_name: str = ""
    status: ControlStatus = ControlStatus.MISSING
    gap_description: str = ""


class CoverageAssessment(BaseModel):
    """Coverage assessment for a framework."""

    framework: Framework = Framework.SOC2
    total_requirements: int = 0
    implemented: int = 0
    partial: int = 0
    missing: int = 0
    not_applicable: int = 0
    coverage_pct: float = 0.0


class ComplianceGap(BaseModel):
    """An identified compliance gap."""

    framework: Framework = Framework.SOC2
    requirement_id: str = ""
    requirement_name: str = ""
    current_status: ControlStatus = ControlStatus.MISSING
    risk_level: str = ""
    remediation_priority: str = ""
    estimated_effort: str = ""


class RemediationPlan(BaseModel):
    """Remediation plan for a compliance gap."""

    gap_id: str = ""
    framework: Framework = Framework.SOC2
    requirement_id: str = ""
    action_items: list[str] = Field(
        default_factory=list,
    )
    owner: str = ""
    timeline: str = ""
    estimated_cost: str = ""
    priority: str = ""


class ComplianceGapAnalyzerState(BaseModel):
    """Full state for a compliance gap analysis run."""

    # Input
    tenant_id: str = ""
    request_id: str = ""
    frameworks: list[str] = Field(
        default_factory=list,
    )

    # Pipeline data
    controls_inventoried: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    mappings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    coverage_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    gaps: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    remediation_plans: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    overall_compliance_pct: float = 0.0
    framework_scores: dict[str, float] = Field(
        default_factory=dict,
    )

    # Workflow tracking
    current_stage: str = ComplianceStage.INVENTORY_CONTROLS
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    error: str = ""
