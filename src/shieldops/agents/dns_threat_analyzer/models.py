"""DNS Threat Analyzer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DTAStage(StrEnum):
    COLLECT_DNS_LOGS = "collect_dns_logs"
    ANALYZE_PATTERNS = "analyze_patterns"
    DETECT_THREATS = "detect_threats"
    CLASSIFY_DOMAINS = "classify_domains"
    ENFORCE_BLOCKS = "enforce_blocks"
    REPORT = "report"


class DNSThreatType(StrEnum):
    TUNNELING = "tunneling"
    DGA_DOMAIN = "dga_domain"
    REBINDING = "rebinding"
    CACHE_POISONING = "cache_poisoning"
    TYPOSQUAT = "typosquat"
    FAST_FLUX = "fast_flux"


class DomainRisk(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    NEWLY_REGISTERED = "newly_registered"
    PARKED = "parked"
    BENIGN = "benign"


class DNSQuery(BaseModel):
    """A single DNS query log entry."""

    id: str = ""
    timestamp: str = ""
    source_ip: str = ""
    query_name: str = ""
    query_type: str = "A"
    response_ip: str = ""
    response_code: str = "NOERROR"
    ttl: int = 300
    resolver: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0


class DNSPattern(BaseModel):
    """An observed DNS traffic pattern."""

    id: str = ""
    source_ip: str = ""
    domain: str = ""
    query_count: int = 0
    unique_subdomains: int = 0
    avg_ttl: float = 0.0
    avg_payload_bytes: float = 0.0
    distinct_ips: int = 0
    entropy_score: float = 0.0
    time_span_minutes: int = 0


class DNSThreat(BaseModel):
    """A detected DNS-based threat."""

    id: str = ""
    threat_type: DNSThreatType = DNSThreatType.DGA_DOMAIN
    domain: str = ""
    source_ip: str = ""
    confidence: float = 0.0
    severity: str = "medium"
    evidence: list[str] = Field(default_factory=list)
    ioc_match: bool = False


class DomainClassification(BaseModel):
    """Classification result for a domain."""

    id: str = ""
    domain: str = ""
    risk: DomainRisk = DomainRisk.BENIGN
    threat_type: DNSThreatType | None = None
    registrar: str = ""
    age_days: int = -1
    whois_privacy: bool = False
    reputation_score: float = 0.0


class BlockEnforcement(BaseModel):
    """Result of a DNS block enforcement action."""

    id: str = ""
    domain: str = ""
    action: str = ""
    status: str = ""
    resolver_updated: bool = False
    firewall_rule_id: str = ""
    rollback_available: bool = True


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class DNSThreatAnalyzerState(BaseModel):
    """Main state for the DNS Threat Analyzer agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: DTAStage = DTAStage.COLLECT_DNS_LOGS

    dns_queries: list[DNSQuery] = Field(
        default_factory=list,
    )
    patterns: list[DNSPattern] = Field(
        default_factory=list,
    )
    threats: list[DNSThreat] = Field(
        default_factory=list,
    )
    classifications: list[DomainClassification] = Field(
        default_factory=list,
    )
    enforcements: list[BlockEnforcement] = Field(
        default_factory=list,
    )

    report: str = ""
    total_queries_analyzed: int = 0
    threats_detected: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
