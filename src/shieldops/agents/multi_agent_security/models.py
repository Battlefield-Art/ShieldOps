"""State models for the Multi-Agent Security LangGraph workflow."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SecurityStage(StrEnum):
    """Stages of the multi-agent security analysis pipeline."""

    DISCOVER = "discover_interactions"
    MAP_TRUST = "map_trust_chains"
    VERIFY = "verify_communications"
    DETECT = "detect_anomalies"
    ENFORCE = "enforce_policies"
    REPORT = "report"


class TrustLevel(StrEnum):
    """Trust classification for an agent within a coordination chain."""

    VERIFIED = "verified"
    PROVISIONAL = "provisional"
    UNTRUSTED = "untrusted"
    COMPROMISED = "compromised"


class InteractionVerdict(StrEnum):
    """Verdict assigned to an evaluated agent-to-agent interaction."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class AgentInteraction(BaseModel):
    """A single observed interaction between two agents."""

    interaction_id: str = ""
    source_agent: str = ""
    target_agent: str = ""
    channel: str = ""
    message_type: str = ""
    payload_hash: str = ""
    timestamp: datetime | None = None
    tools_requested: list[str] = Field(default_factory=list)
    data_labels: list[str] = Field(default_factory=list)
    verdict: InteractionVerdict = InteractionVerdict.SAFE


class TrustChain(BaseModel):
    """A delegation / coordination trust chain across multiple agents."""

    chain_id: str = ""
    root_agent: str = ""
    chain: list[str] = Field(default_factory=list)
    trust_level: TrustLevel = TrustLevel.PROVISIONAL
    delegation_depth: int = 0
    privilege_escalation_detected: bool = False
    proxy_tool_access: list[str] = Field(default_factory=list)


class CommunicationVerification(BaseModel):
    """Result of verifying a single agent communication."""

    interaction_id: str = ""
    hash_valid: bool = True
    identity_verified: bool = True
    replay_detected: bool = False
    impersonation_risk: float = 0.0
    tampering_indicators: list[str] = Field(default_factory=list)


class InteractionAnomaly(BaseModel):
    """An anomaly detected in agent-to-agent interactions."""

    anomaly_id: str = ""
    anomaly_type: str = ""
    severity: str = "low"
    description: str = ""
    source_agent: str = ""
    target_agent: str = ""
    confidence: float = 0.0
    mitre_technique: str = ""
    evidence: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Workflow tracking
# ---------------------------------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the multi-agent security workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


# ---------------------------------------------------------------------------
# LangGraph state
# ---------------------------------------------------------------------------


class MultiAgentSecurityState(BaseModel):
    """Full state for a multi-agent security workflow run."""

    # Input
    tenant_id: str = ""
    scan_scope: dict[str, Any] = Field(default_factory=dict)
    agent_registry: list[str] = Field(default_factory=list)

    # Discovery
    interactions: list[dict[str, Any]] = Field(default_factory=list)

    # Trust chain mapping
    trust_chains: list[dict[str, Any]] = Field(default_factory=list)

    # Communication verification
    verification_results: list[dict[str, Any]] = Field(default_factory=list)

    # Anomaly detection
    anomalies: list[dict[str, Any]] = Field(default_factory=list)

    # Policy enforcement
    enforcement_actions: list[dict[str, Any]] = Field(default_factory=list)
    blocked_interactions: int = 0
    quarantined_agents: list[str] = Field(default_factory=list)

    # Report
    report: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    threats_detected: bool = False

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str | None = None
