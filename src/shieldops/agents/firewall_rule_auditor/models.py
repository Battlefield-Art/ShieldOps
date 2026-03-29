"""Firewall Rule Auditor Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AuditStage(StrEnum):
    COLLECT_RULES = "collect_rules"
    DETECT_VIOLATIONS = "detect_violations"
    CLASSIFY_RISKS = "classify_risks"
    CHECK_COMPLIANCE = "check_compliance"
    RECOMMEND_FIXES = "recommend_fixes"
    REPORT = "report"


class RuleRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FirewallProvider(StrEnum):
    AWS_SG = "aws_sg"
    AZURE_NSG = "azure_nsg"
    GCP_FIREWALL = "gcp_firewall"


class FirewallRule(BaseModel):
    """A single firewall / security-group rule."""

    id: str = ""
    provider: FirewallProvider = FirewallProvider.AWS_SG
    group_id: str = ""
    group_name: str = ""
    direction: str = "inbound"  # inbound | outbound
    protocol: str = "tcp"
    port_range: str = ""
    source: str = ""
    destination: str = ""
    action: str = "allow"  # allow | deny
    description: str = ""
    region: str = ""
    last_hit: float = 0.0
    created_at: float = Field(default_factory=time.time)
    tags: dict[str, str] = Field(default_factory=dict)


class RuleViolation(BaseModel):
    """A violation detected on a firewall rule."""

    id: str = ""
    rule_id: str = ""
    provider: FirewallProvider = FirewallProvider.AWS_SG
    violation_type: str = ""
    risk: RuleRisk = RuleRisk.MEDIUM
    description: str = ""
    recommendation: str = ""
    compliance_refs: list[str] = Field(default_factory=list)
    auto_fixable: bool = False


class AuditFinding(BaseModel):
    """An aggregated finding from the audit with recommended fix."""

    id: str = ""
    violation_ids: list[str] = Field(default_factory=list)
    title: str = ""
    risk: RuleRisk = RuleRisk.MEDIUM
    affected_rules: int = 0
    fix_action: str = ""
    applied: bool = False
    success: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class FirewallAuditState(BaseModel):
    """Main state for the Firewall Rule Auditor agent graph."""

    request_id: str = ""
    stage: AuditStage = AuditStage.COLLECT_RULES
    tenant_id: str = ""
    providers: list[str] = Field(default_factory=list)

    # Collected rules
    firewall_rules: list[dict[str, Any]] = Field(default_factory=list)

    # Detected violations
    violations: list[dict[str, Any]] = Field(default_factory=list)

    # Compliance check results
    compliance_results: list[dict[str, Any]] = Field(default_factory=list)

    # Recommended fixes / findings
    findings: list[dict[str, Any]] = Field(default_factory=list)

    # Overall audit score (0-100, higher = more secure)
    audit_score: float = 0.0

    # Stats / summary
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""

    # Timing
    session_start: float = Field(default_factory=time.time)
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
