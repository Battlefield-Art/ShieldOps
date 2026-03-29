"""WAF Manager — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class WAFStage(StrEnum):
    INGEST = "ingest"
    ANALYZE_ATTACKS = "analyze_attacks"
    EVALUATE_COVERAGE = "evaluate_coverage"
    TUNE_RULES = "tune_rules"
    REDUCE_FALSE_POSITIVES = "reduce_false_positives"
    AUTO_BLOCK = "auto_block"
    REPORT = "report"


class AttackCategory(StrEnum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    BROKEN_AUTH = "broken_auth"
    SENSITIVE_DATA = "sensitive_data"
    XXE = "xxe"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    CSRF = "csrf"
    BOT_ATTACK = "bot_attack"
    API_ABUSE = "api_abuse"
    UNKNOWN = "unknown"


class RuleAction(StrEnum):
    BLOCK = "block"
    ALLOW = "allow"
    LOG = "log"
    CHALLENGE = "challenge"
    RATE_LIMIT = "rate_limit"
    REDIRECT = "redirect"


class WAFRule(BaseModel):
    """A single WAF rule definition."""

    rule_id: str = ""
    name: str = ""
    description: str = ""
    pattern: str = ""
    action: RuleAction = RuleAction.BLOCK
    category: AttackCategory = AttackCategory.UNKNOWN
    severity: str = "medium"
    enabled: bool = True
    false_positive_rate: float = 0.0
    hit_count: int = 0
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackEvent(BaseModel):
    """A detected attack event from WAF logs."""

    event_id: str = ""
    timestamp: float = 0.0
    source_ip: str = ""
    target_url: str = ""
    method: str = "GET"
    category: AttackCategory = AttackCategory.UNKNOWN
    matched_rule_id: str = ""
    action_taken: RuleAction = RuleAction.LOG
    payload_snippet: str = ""
    severity: str = "medium"
    risk_score: float = 0.0
    is_false_positive: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class CoverageGap(BaseModel):
    """An OWASP Top 10 coverage gap identified by analysis."""

    owasp_id: str = ""
    owasp_name: str = ""
    category: AttackCategory = AttackCategory.UNKNOWN
    covered: bool = False
    rule_count: int = 0
    gap_description: str = ""
    recommended_rules: list[str] = Field(default_factory=list)
    severity: str = "high"


class WAFManagerState(BaseModel):
    """Main state for the WAF Manager graph."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: WAFStage = WAFStage.INGEST
    waf_provider: str = ""
    time_window_hours: int = 24

    # Rules
    active_rules: list[dict[str, Any]] = Field(default_factory=list)
    proposed_rules: list[dict[str, Any]] = Field(default_factory=list)
    disabled_rules: list[dict[str, Any]] = Field(default_factory=list)

    # Attack analysis
    attack_events: list[dict[str, Any]] = Field(default_factory=list)
    attack_summary: dict[str, Any] = Field(default_factory=dict)
    top_attack_sources: list[dict[str, Any]] = Field(default_factory=list)

    # Coverage
    coverage_gaps: list[dict[str, Any]] = Field(default_factory=list)
    owasp_coverage_pct: float = 0.0

    # False positives
    false_positives: list[dict[str, Any]] = Field(default_factory=list)
    fp_reduction_actions: list[dict[str, Any]] = Field(default_factory=list)

    # Auto-blocking
    auto_blocked_ips: list[str] = Field(default_factory=list)
    block_recommendations: list[dict[str, Any]] = Field(default_factory=list)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
