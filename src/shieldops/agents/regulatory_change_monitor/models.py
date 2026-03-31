"""State models for the Regulatory Change Monitor Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class RCMStage(StrEnum):
    """Stages in the regulatory change monitoring lifecycle."""

    MONITOR_SOURCES = "monitor_sources"
    PARSE_CHANGES = "parse_changes"
    ASSESS_IMPACT = "assess_impact"
    MAP_CONTROLS = "map_controls"
    GENERATE_ACTIONS = "generate_actions"
    REPORT = "report"


class RegulatoryFramework(StrEnum):
    """Regulatory frameworks tracked."""

    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"
    CCPA = "ccpa"
    EU_AI_ACT = "eu_ai_act"


class ImpactLevel(StrEnum):
    """Impact classification for regulatory changes."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# --- Domain models ---


class RegulatoryChange(BaseModel):
    """A detected regulatory change or update."""

    change_id: str = ""
    framework: RegulatoryFramework = RegulatoryFramework.NIST_CSF
    title: str = ""
    description: str = ""
    source_url: str = ""
    effective_date: str = ""
    published_date: str = ""
    change_type: str = ""
    sections_affected: list[str] = Field(
        default_factory=list,
    )


class ImpactAssessment(BaseModel):
    """Impact assessment for a regulatory change."""

    change_id: str = ""
    impact_level: ImpactLevel = ImpactLevel.LOW
    affected_controls: list[str] = Field(
        default_factory=list,
    )
    affected_processes: list[str] = Field(
        default_factory=list,
    )
    compliance_gap: bool = False
    estimated_effort_hours: int = 0
    summary: str = ""


class ControlMapping(BaseModel):
    """Mapping between regulatory requirement and internal control."""

    change_id: str = ""
    control_id: str = ""
    control_name: str = ""
    current_status: str = ""
    gap_identified: bool = False
    remediation_needed: bool = False
    framework: RegulatoryFramework = RegulatoryFramework.NIST_CSF


class ActionItem(BaseModel):
    """Action item generated from regulatory change analysis."""

    action_id: str = ""
    change_id: str = ""
    title: str = ""
    description: str = ""
    priority: str = "medium"
    assignee: str = ""
    due_date: str = ""
    status: str = "open"


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the monitor workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class RegulatoryChangeMonitorState(BaseModel):
    """Full state for a regulatory change monitor run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: RCMStage = RCMStage.MONITOR_SOURCES

    # Inputs
    scan_name: str = ""
    frameworks: list[RegulatoryFramework] = Field(
        default_factory=list,
    )
    scope: dict[str, Any] = Field(default_factory=dict)
    sources: list[str] = Field(default_factory=list)

    # Pipeline fields
    changes: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    parsed_changes: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    impact_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    control_mappings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    action_items: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_changes: int = 0
    critical_changes: int = 0
    compliance_gaps: int = 0
    actions_generated: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
