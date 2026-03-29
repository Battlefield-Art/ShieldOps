"""Spam Filter Manager Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SpamStage(StrEnum):
    COLLECT_RULES = "collect_rules"
    CLASSIFY_MESSAGES = "classify_messages"
    TUNE_FILTERS = "tune_filters"
    ANALYZE_FALSE_POSITIVES = "analyze_false_positives"
    MANAGE_QUARANTINE = "manage_quarantine"
    REPORT = "report"


class SpamCategory(StrEnum):
    MARKETING = "marketing"
    NEWSLETTER = "newsletter"
    PROMOTIONAL = "promotional"
    PHISHING = "phishing"
    MALWARE = "malware"
    SCAM = "scam"
    BULK = "bulk"
    LEGITIMATE = "legitimate"


class FilterAction(StrEnum):
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    REJECT = "reject"
    TAG = "tag"
    REDIRECT = "redirect"
    DELETE = "delete"


class SpamRule(BaseModel):
    """Spam filter rule definition."""

    id: str = ""
    name: str = ""
    pattern: str = ""
    category: SpamCategory = SpamCategory.BULK
    action: FilterAction = FilterAction.QUARANTINE
    score_threshold: float = 5.0
    enabled: bool = True
    false_positive_rate: float = 0.0
    hit_count: int = 0
    last_triggered: float = 0.0


class ClassificationResult(BaseModel):
    """Message classification result."""

    message_id: str = ""
    sender: str = ""
    subject: str = ""
    category: SpamCategory = SpamCategory.LEGITIMATE
    spam_score: float = 0.0
    action_taken: FilterAction = FilterAction.ALLOW
    matched_rules: list[str] = Field(default_factory=list)
    is_false_positive: bool = False
    confidence: float = 0.0


class SpamFilterManagerState(BaseModel):
    """Full state for the Spam Filter Manager agent."""

    request_id: str = ""
    stage: SpamStage = SpamStage.COLLECT_RULES
    tenant_id: str = ""
    rules: list[dict[str, Any]] = Field(default_factory=list)
    total_rules: int = 0
    classifications: list[dict[str, Any]] = Field(default_factory=list)
    messages_classified: int = 0
    spam_detected: int = 0
    tuning_suggestions: list[dict[str, Any]] = Field(default_factory=list)
    rules_tuned: int = 0
    false_positives: list[dict[str, Any]] = Field(default_factory=list)
    false_positive_rate: float = 0.0
    quarantine_items: list[dict[str, Any]] = Field(default_factory=list)
    quarantine_count: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
