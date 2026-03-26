"""DNS Security Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DNSStage(StrEnum):
    COLLECT_DNS = "collect_dns"
    DETECT_TUNNELING = "detect_tunneling"
    DETECT_DGA = "detect_dga"
    DETECT_TYPOSQUATTING = "detect_typosquatting"
    RESPOND = "respond"
    REPORT = "report"


class DNSThreatType(StrEnum):
    TUNNELING = "tunneling"
    DGA = "dga"
    TYPOSQUATTING = "typosquatting"
    EXFILTRATION = "exfiltration"
    C2_COMMUNICATION = "c2_communication"
    FAST_FLUX = "fast_flux"


class DNSSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DNSQuery(BaseModel):
    """A DNS query record for analysis."""

    id: str = ""
    domain: str = ""
    query_type: str = "A"
    source_ip: str = ""
    response_ip: str = ""
    ttl: int = 0
    timestamp: datetime | None = None
    response_code: str = "NOERROR"
    query_size: int = 0
    response_size: int = 0


class DNSThreat(BaseModel):
    """A DNS-based threat detection."""

    id: str = ""
    threat_type: DNSThreatType = DNSThreatType.TUNNELING
    domain: str = ""
    severity: DNSSeverity = DNSSeverity.MEDIUM
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    mitre_technique: str = ""
    source_ips: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    description: str = ""


class DNSResponse(BaseModel):
    """A response action for a DNS threat."""

    threat_id: str = ""
    action: str = ""
    target: str = ""
    status: str = "pending"
    details: str = ""


class DNSSecurityState(BaseModel):
    """Main state for the DNS Security agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: DNSStage = DNSStage.COLLECT_DNS

    # Collected DNS queries
    dns_queries: list[dict[str, Any]] = Field(default_factory=list)

    # Detected threats
    threats: list[dict[str, Any]] = Field(default_factory=list)

    # Response actions
    responses: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    summary: str = ""
    total_queries: int = 0
    total_threats: int = 0

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
