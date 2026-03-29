"""Alert Enrichment Engine Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EnrichmentStage(StrEnum):
    INGEST_ALERT = "ingest_alert"
    LOOKUP_CONTEXT = "lookup_context"
    CORRELATE_INTEL = "correlate_intel"
    SCORE_PRIORITY = "score_priority"
    ROUTE = "route"
    REPORT = "report"


class EnrichmentSource(StrEnum):
    THREAT_INTEL = "threat_intel"
    ASSET_DB = "asset_db"
    VULN_SCANNER = "vuln_scanner"
    IDENTITY_PROVIDER = "identity_provider"
    GEO_IP = "geo_ip"
    WHOIS = "whois"


class AlertPriority(StrEnum):
    P1_CRITICAL = "p1_critical"
    P2_HIGH = "p2_high"
    P3_MEDIUM = "p3_medium"
    P4_LOW = "p4_low"
    P5_INFO = "p5_info"


class AlertEnrichmentEngineState(BaseModel):
    request_id: str = ""
    stage: EnrichmentStage = EnrichmentStage.INGEST_ALERT
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
