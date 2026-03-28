"""State models for the Risk Prioritizer Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PrioritizerStage(StrEnum):
    """Stages of the risk prioritizer workflow."""

    COLLECT_FINDINGS = "collect_findings"
    ENRICH_CONTEXT = "enrich_context"
    SCORE_RISK = "score_risk"
    RANK_FINDINGS = "rank_findings"
    GENERATE_ACTION_PLAN = "generate_action_plan"
    REPORT = "report"


class RiskFactor(StrEnum):
    """Factors contributing to risk score."""

    EXPLOITABILITY = "exploitability"
    BLAST_RADIUS = "blast_radius"
    ASSET_CRITICALITY = "asset_criticality"
    DATA_SENSITIVITY = "data_sensitivity"
    REGULATORY_IMPACT = "regulatory_impact"


class ActionUrgency(StrEnum):
    """Urgency levels for remediation actions."""

    IMMEDIATE = "immediate"
    URGENT = "urgent"
    SCHEDULED = "scheduled"
    DEFERRED = "deferred"
    ACCEPTED = "accepted"


class FindingInput(BaseModel):
    """A finding to be risk-prioritized."""

    id: str = ""
    title: str = ""
    severity: str = ""
    asset: str = ""
    description: str = ""
    cvss_score: float = 0.0
    cve_id: str = ""
    source_agent: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContextEnrichment(BaseModel):
    """Business context enrichment for a finding."""

    finding_id: str = ""
    asset_criticality: str = ""
    data_sensitivity: str = ""
    exposure_type: str = ""
    regulatory_scope: list[str] = Field(default_factory=list)
    business_owner: str = ""
    environment: str = ""


class RiskScore(BaseModel):
    """Composite risk score for a finding."""

    finding_id: str = ""
    composite_score: float = 0.0
    exploitability: float = 0.0
    blast_radius: float = 0.0
    asset_criticality: float = 0.0
    data_sensitivity: float = 0.0
    regulatory_impact: float = 0.0
    epss_score: float = 0.0


class RankedFinding(BaseModel):
    """A finding with its final rank."""

    finding_id: str = ""
    title: str = ""
    rank: int = 0
    composite_score: float = 0.0
    urgency: ActionUrgency = ActionUrgency.SCHEDULED
    top_risk_factors: list[str] = Field(default_factory=list)


class ActionPlan(BaseModel):
    """Remediation action plan for a finding."""

    finding_id: str = ""
    urgency: ActionUrgency = ActionUrgency.SCHEDULED
    recommended_action: str = ""
    estimated_effort_hours: float = 0.0
    assigned_team: str = ""
    deadline: str = ""
    dependencies: list[str] = Field(default_factory=list)


class RiskPrioritizerState(BaseModel):
    """Full state for the risk prioritizer workflow."""

    # Input
    tenant_id: str = ""
    request_id: str = ""

    # Pipeline data
    findings_collected: list[FindingInput] = Field(default_factory=list)
    enrichments: list[ContextEnrichment] = Field(default_factory=list)
    risk_scores: list[RiskScore] = Field(default_factory=list)
    ranked_findings: list[RankedFinding] = Field(default_factory=list)
    action_plans: list[ActionPlan] = Field(default_factory=list)

    # Metrics
    critical_count: int = 0
    immediate_actions: int = 0

    # Workflow tracking
    current_stage: PrioritizerStage = PrioritizerStage.COLLECT_FINDINGS
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_duration_ms: int = 0
