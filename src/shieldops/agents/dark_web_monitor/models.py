"""Dark Web Monitor Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MonitorStage(StrEnum):
    CRAWL_SOURCES = "crawl_sources"
    EXTRACT_MENTIONS = "extract_mentions"
    MATCH_ASSETS = "match_assets"
    ASSESS_RISK = "assess_risk"
    ALERT = "alert"
    REPORT = "report"


class SourceType(StrEnum):
    PASTE_SITE = "paste_site"
    FORUM = "forum"
    MARKETPLACE = "marketplace"
    TELEGRAM = "telegram"
    ONION_SITE = "onion_site"
    IRC = "irc"


class ThreatLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class DarkWebMonitorState(BaseModel):
    request_id: str = ""
    stage: MonitorStage = MonitorStage.CRAWL_SOURCES
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
