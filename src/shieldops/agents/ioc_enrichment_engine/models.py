"""State models for the IOC Enrichment Engine Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IEEStage(StrEnum):
    """Stages of the IOC enrichment workflow."""

    COLLECT_IOCS = "collect_iocs"
    QUERY_SOURCES = "query_sources"
    CORRELATE_CONTEXT = "correlate_context"
    ASSESS_RISK = "assess_risk"
    TAG_INDICATORS = "tag_indicators"
    REPORT = "report"


class IOCType(StrEnum):
    """Types of indicators of compromise."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    CERTIFICATE = "certificate"


class EnrichmentConfidence(StrEnum):
    """Confidence levels for enrichment results."""

    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class IOCEnrichmentEngineState(BaseModel):
    """Full state for IOC enrichment workflow."""

    request_id: str = ""
    stage: IEEStage = IEEStage.COLLECT_IOCS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    stats: dict[str, Any] = Field(
        default_factory=dict,
    )
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
