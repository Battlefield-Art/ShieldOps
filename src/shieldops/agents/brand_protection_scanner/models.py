"""Brand Protection Scanner Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ScanStage(StrEnum):
    DISCOVER_DOMAINS = "discover_domains"
    ANALYZE_SIMILARITY = "analyze_similarity"
    CHECK_CERTIFICATES = "check_certificates"
    CLASSIFY_THREATS = "classify_threats"
    TAKEDOWN = "takedown"
    REPORT = "report"


class ThreatType(StrEnum):
    TYPOSQUAT = "typosquat"
    HOMOGLYPH = "homoglyph"
    PHISHING_KIT = "phishing_kit"
    FAKE_APP = "fake_app"
    SOCIAL_IMPERSONATION = "social_impersonation"
    SUBDOMAIN_ABUSE = "subdomain_abuse"


class ActionStatus(StrEnum):
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    TAKEDOWN_REQUESTED = "takedown_requested"
    RESOLVED = "resolved"
    MONITORING = "monitoring"


class BrandProtectionScannerState(BaseModel):
    request_id: str = ""
    stage: ScanStage = ScanStage.DISCOVER_DOMAINS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
