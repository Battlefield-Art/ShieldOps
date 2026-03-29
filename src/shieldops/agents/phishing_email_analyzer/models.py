"""Phishing Email Analyzer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PhishingStage(StrEnum):
    INGEST_EMAIL = "ingest_email"
    ANALYZE_SENDER = "analyze_sender"
    ANALYZE_URLS = "analyze_urls"
    ANALYZE_CONTENT = "analyze_content"
    SCORE_RISK = "score_risk"
    REPORT = "report"


class PhishingIndicator(StrEnum):
    SPOOFED_SENDER = "spoofed_sender"
    MALICIOUS_URL = "malicious_url"
    BRAND_IMPERSONATION = "brand_impersonation"
    URGENCY_LANGUAGE = "urgency_language"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    ATTACHMENT_RISK = "attachment_risk"
    DISPLAY_NAME_SPOOF = "display_name_spoof"
    HOMOGRAPH_DOMAIN = "homograph_domain"


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class EmailAnalysis(BaseModel):
    """Analyzed email record."""

    id: str = ""
    sender: str = ""
    sender_domain: str = ""
    display_name: str = ""
    subject: str = ""
    body_preview: str = ""
    has_attachments: bool = False
    attachment_types: list[str] = Field(default_factory=list)
    sender_reputation: float = 0.0
    auth_status: str = ""
    indicators: list[str] = Field(default_factory=list)


class URLAnalysis(BaseModel):
    """Analyzed URL from email."""

    url: str = ""
    domain: str = ""
    is_shortened: bool = False
    redirect_chain: list[str] = Field(default_factory=list)
    final_url: str = ""
    is_malicious: bool = False
    brand_impersonated: str = ""
    has_login_form: bool = False
    ssl_valid: bool = True
    domain_age_days: int = 0
    risk_score: float = 0.0


class PhishingEmailAnalyzerState(BaseModel):
    """Full state for the Phishing Email Analyzer agent."""

    request_id: str = ""
    stage: PhishingStage = PhishingStage.INGEST_EMAIL
    tenant_id: str = ""
    emails: list[dict[str, Any]] = Field(default_factory=list)
    email_analyses: list[dict[str, Any]] = Field(default_factory=list)
    total_emails: int = 0
    url_analyses: list[dict[str, Any]] = Field(default_factory=list)
    malicious_urls: int = 0
    content_analyses: list[dict[str, Any]] = Field(default_factory=list)
    brand_impersonations: int = 0
    risk_scores: list[dict[str, Any]] = Field(default_factory=list)
    high_risk_count: int = 0
    avg_risk_score: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
