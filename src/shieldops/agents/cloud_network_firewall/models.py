"""Cloud Network Firewall Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CNFStage(StrEnum):
    COLLECT_RULES = "collect_rules"
    ANALYZE_COVERAGE = "analyze_coverage"
    DETECT_OVERPERMISSIVE = "detect_overpermissive"
    FIND_SHADOW_RULES = "find_shadow_rules"
    OPTIMIZE_RULES = "optimize_rules"
    REPORT = "report"


class RuleSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CloudPlatform(StrEnum):
    AWS_SG = "aws_sg"
    GCP_FIREWALL = "gcp_firewall"
    AZURE_NSG = "azure_nsg"
    K8S_NETWORK_POLICY = "k8s_network_policy"


class FirewallRule(BaseModel):
    """A single firewall rule from any cloud platform."""

    id: str = ""
    platform: CloudPlatform = CloudPlatform.AWS_SG
    group_id: str = ""
    rule_name: str = ""
    direction: str = "ingress"  # ingress / egress
    protocol: str = "tcp"
    port_range: str = ""
    source_cidr: str = ""
    destination_cidr: str = ""
    action: str = "allow"  # allow / deny
    priority: int = 1000
    description: str = ""
    region: str = ""
    tags: dict[str, str] = Field(default_factory=dict)
    last_hit: float = 0.0
    hit_count: int = 0


class CoverageAnalysis(BaseModel):
    """Coverage analysis for a set of firewall rules."""

    id: str = ""
    platform: CloudPlatform = CloudPlatform.AWS_SG
    group_id: str = ""
    total_rules: int = 0
    ingress_rules: int = 0
    egress_rules: int = 0
    allow_rules: int = 0
    deny_rules: int = 0
    protocols_covered: list[str] = Field(default_factory=list)
    port_coverage_pct: float = 0.0
    unused_rules: int = 0
    coverage_score: float = Field(default=0.0, ge=0.0, le=100.0)


class OverpermissiveRule(BaseModel):
    """A firewall rule flagged as overly permissive."""

    id: str = ""
    rule_id: str = ""
    platform: CloudPlatform = CloudPlatform.AWS_SG
    severity: RuleSeverity = RuleSeverity.HIGH
    reason: str = ""
    source_cidr: str = ""
    port_range: str = ""
    protocol: str = ""
    recommendation: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    auto_fixable: bool = False


class ShadowRule(BaseModel):
    """A shadow rule that is masked by a higher-priority rule."""

    id: str = ""
    shadowed_rule_id: str = ""
    shadowing_rule_id: str = ""
    platform: CloudPlatform = CloudPlatform.AWS_SG
    reason: str = ""
    shadowed_action: str = ""
    shadowing_action: str = ""
    impact: str = ""
    removable: bool = False


class RuleOptimization(BaseModel):
    """An optimization recommendation for firewall rules."""

    id: str = ""
    platform: CloudPlatform = CloudPlatform.AWS_SG
    optimization_type: str = ""  # merge / remove / restrict / reorder
    affected_rule_ids: list[str] = Field(default_factory=list)
    description: str = ""
    risk_reduction: float = Field(default=0.0, ge=0.0, le=100.0)
    auto_applicable: bool = False
    applied: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudNetworkFirewallState(BaseModel):
    """Main state for the Cloud Network Firewall agent graph."""

    request_id: str = ""
    stage: CNFStage = CNFStage.COLLECT_RULES
    tenant_id: str = ""
    platforms: list[str] = Field(default_factory=list)

    # Collected rules
    firewall_rules: list[dict[str, Any]] = Field(default_factory=list)

    # Coverage analysis
    coverage_results: list[dict[str, Any]] = Field(default_factory=list)

    # Overpermissive detection
    overpermissive_rules: list[dict[str, Any]] = Field(default_factory=list)

    # Shadow rules
    shadow_rules: list[dict[str, Any]] = Field(default_factory=list)

    # Optimizations
    optimizations: list[dict[str, Any]] = Field(default_factory=list)

    # Overall security score
    security_score: float = 0.0

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
