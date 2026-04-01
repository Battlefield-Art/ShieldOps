"""State models for the Unified Policy Compiler Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ------------------------------------------------


class UPCStage(StrEnum):
    """Workflow stages for policy compilation."""

    INGEST_POLICIES = "ingest_policies"
    PARSE_REQUIREMENTS = "parse_requirements"
    RESOLVE_CONFLICTS = "resolve_conflicts"
    COMPILE_RULESET = "compile_ruleset"
    VALIDATE_COVERAGE = "validate_coverage"
    REPORT = "report"


class PolicySource(StrEnum):
    """Source framework for a policy."""

    NIST = "nist"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"


class ConflictResolution(StrEnum):
    """Strategy for resolving policy conflicts."""

    STRICTEST_WINS = "strictest_wins"
    MOST_RECENT = "most_recent"
    MANUAL_REVIEW = "manual_review"
    WEIGHTED_MERGE = "weighted_merge"
    FRAMEWORK_PRIORITY = "framework_priority"


# -- Domain Models -------------------------------------------


class PolicyRecord(BaseModel):
    """An ingested policy record."""

    policy_id: str = ""
    source: PolicySource = PolicySource.NIST
    control_id: str = ""
    title: str = ""
    requirements: list[str] = Field(default_factory=list)


class ParsedRequirement(BaseModel):
    """A parsed policy requirement."""

    requirement_id: str = ""
    source: PolicySource = PolicySource.NIST
    category: str = ""
    text: str = ""
    mandatory: bool = True


class PolicyConflict(BaseModel):
    """A detected policy conflict."""

    conflict_id: str = ""
    requirement_a: str = ""
    requirement_b: str = ""
    conflict_type: str = ""
    resolution: ConflictResolution = ConflictResolution.STRICTEST_WINS


class CompiledRule(BaseModel):
    """A compiled unified rule."""

    rule_id: str = ""
    title: str = ""
    sources: list[str] = Field(default_factory=list)
    conditions: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)


class CoverageResult(BaseModel):
    """Coverage validation result."""

    framework: PolicySource = PolicySource.NIST
    total_controls: int = 0
    covered_controls: int = 0
    coverage_pct: float = 0.0
    gaps: list[str] = Field(default_factory=list)


# -- Reasoning + State ---------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class UnifiedPolicyCompilerState(BaseModel):
    """Full state for the Unified Policy Compiler."""

    request_id: str = ""
    tenant_id: str = ""
    stage: UPCStage = UPCStage.INGEST_POLICIES
    config: dict[str, Any] = Field(default_factory=dict)

    policy_records: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    parsed_requirements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    policy_conflicts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    compiled_rules: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    coverage_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
