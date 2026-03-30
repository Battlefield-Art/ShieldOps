"""Compliance Gap Analyzer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CGAStage(StrEnum):
    SCAN_POSTURE = "scan_posture"
    MAP_REQUIREMENTS = "map_requirements"
    IDENTIFY_GAPS = "identify_gaps"
    PRIORITIZE_RISKS = "prioritize_risks"
    GENERATE_PLAN = "generate_plan"
    REPORT = "report"


class RegulatoryDomain(StrEnum):
    FINANCIAL = "financial"
    HEALTHCARE = "healthcare"
    GOVERNMENT = "government"
    TECHNOLOGY = "technology"
    RETAIL = "retail"
    ENERGY = "energy"


class GapSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class PostureScan(BaseModel):
    """Current security posture snapshot."""

    scan_id: str = ""
    domain: str = ""
    controls_total: int = 0
    controls_implemented: int = 0
    controls_partial: int = 0
    controls_missing: int = 0
    score: float = 0.0
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )


class RegulatoryRequirement(BaseModel):
    """A regulatory requirement to assess against."""

    requirement_id: str = ""
    framework: str = ""
    domain: RegulatoryDomain = RegulatoryDomain.TECHNOLOGY
    title: str = ""
    description: str = ""
    control_mappings: list[str] = Field(
        default_factory=list,
    )
    mandatory: bool = True


class SecurityGap(BaseModel):
    """An identified gap between posture and requirements."""

    gap_id: str = ""
    requirement_id: str = ""
    framework: str = ""
    severity: GapSeverity = GapSeverity.MEDIUM
    description: str = ""
    current_state: str = ""
    required_state: str = ""
    affected_controls: list[str] = Field(
        default_factory=list,
    )


class RiskPriority(BaseModel):
    """Risk-prioritized gap with business impact."""

    gap_id: str = ""
    severity: GapSeverity = GapSeverity.MEDIUM
    risk_score: float = 0.0
    business_impact: str = ""
    regulatory_penalty: str = ""
    likelihood: float = 0.0


class RemediationPlan(BaseModel):
    """Actionable remediation plan for a gap."""

    gap_id: str = ""
    title: str = ""
    steps: list[str] = Field(default_factory=list)
    estimated_effort_days: int = 0
    owner: str = ""
    priority_rank: int = 0
    dependencies: list[str] = Field(
        default_factory=list,
    )


class ReasoningStep(BaseModel):
    """A single reasoning step in the agent chain."""

    step: str = ""
    detail: str = ""


class ComplianceGapAnalyzerState(BaseModel):
    """Main state for the Compliance Gap Analyzer graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CGAStage = CGAStage.SCAN_POSTURE
    domains: list[RegulatoryDomain] = Field(
        default_factory=list,
    )

    # Pipeline fields
    posture_scans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    requirements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    gaps: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_priorities: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    remediation_plans: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    total_gaps: int = 0
    critical_gaps: int = 0
    compliance_score: float = 0.0

    # Output
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    error: str = ""
