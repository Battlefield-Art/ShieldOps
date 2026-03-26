"""State models for the Trust Relationship Mapper Agent."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TrustStage(StrEnum):
    """Stages of the trust mapping pipeline."""

    DISCOVER_TRUST_BOUNDARIES = "discover_trust_boundaries"
    MAP_FEDERATION = "map_federation"
    ANALYZE_DELEGATION_CHAINS = "analyze_delegation_chains"
    DETECT_TRUST_ABUSE = "detect_trust_abuse"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class TrustType(StrEnum):
    """Types of trust relationships."""

    FEDERATION = "federation"
    DELEGATION = "delegation"
    CROSS_ACCOUNT_ROLE = "cross_account_role"
    API_TRUST = "api_trust"
    AI_AGENT_DELEGATION = "ai_agent_delegation"
    MCP_TRUST_CHAIN = "mcp_trust_chain"


class AbuseIndicator(StrEnum):
    """Indicators of trust relationship abuse."""

    STALE_FEDERATION = "stale_federation"
    EXCESSIVE_DELEGATION = "excessive_delegation"
    CROSS_ACCOUNT_PIVOT = "cross_account_pivot"
    TRUST_CHAIN_BYPASS = "trust_chain_bypass"
    ORPHANED_TRUST = "orphaned_trust"


class TrustBoundary(BaseModel):
    """A discovered trust boundary."""

    id: str = ""
    name: str = ""
    boundary_type: str = ""
    source_domain: str = ""
    target_domain: str = ""
    trust_type: TrustType = TrustType.FEDERATION
    protocol: str = ""
    created_at: float = 0.0
    last_used: float = 0.0
    is_bidirectional: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class FederationMapping(BaseModel):
    """Federation relationship between domains."""

    id: str = ""
    source_idp: str = ""
    target_sp: str = ""
    protocol: str = ""
    claims_mapped: list[str] = Field(default_factory=list)
    last_token_issued: float = 0.0
    token_count_30d: int = 0
    risk_score: float = 0.0


class DelegationChain(BaseModel):
    """Chain of delegated permissions."""

    id: str = ""
    chain_depth: int = 0
    principals: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    trust_types: list[str] = Field(default_factory=list)
    effective_permissions: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    is_transitive: bool = False


class TrustAbuse(BaseModel):
    """Detected trust abuse indicator."""

    id: str = ""
    indicator: AbuseIndicator = AbuseIndicator.STALE_FEDERATION
    trust_boundary_id: str = ""
    severity: str = ""
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    detected_at: float = 0.0


class TrustRiskAssessment(BaseModel):
    """Risk assessment for a trust relationship."""

    id: str = ""
    trust_boundary_id: str = ""
    overall_risk: float = 0.0
    risk_factors: list[str] = Field(default_factory=list)
    abuse_indicators: list[str] = Field(default_factory=list)
    recommendation: str = ""
    remediation_priority: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the workflow."""

    step_number: int = 0
    action: str = ""
    input_summary: str = ""
    output_summary: str = ""
    duration_ms: int = 0
    tool_used: str | None = None


class TrustRelationshipMapperState(BaseModel):
    """Full state for a trust mapping run."""

    # Input
    tenant_id: str = ""
    scope: str = "all"

    # Pipeline data
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    federation_mappings: list[FederationMapping] = Field(default_factory=list)
    delegation_chains: list[DelegationChain] = Field(default_factory=list)
    trust_abuses: list[TrustAbuse] = Field(default_factory=list)
    risk_assessments: list[TrustRiskAssessment] = Field(default_factory=list)

    # Metrics
    total_boundaries: int = 0
    total_abuses_detected: int = 0
    avg_risk_score: float = 0.0

    # Workflow tracking
    current_stage: TrustStage = TrustStage.DISCOVER_TRUST_BOUNDARIES
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
    session_duration_ms: int = 0
