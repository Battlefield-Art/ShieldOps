"""DNS Firewall Controller Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DFCStage(StrEnum):
    INGEST_QUERIES = "ingest_queries"
    ANALYZE_DOMAINS = "analyze_domains"
    CHECK_REPUTATION = "check_reputation"
    DETECT_TUNNELING = "detect_tunneling"
    ENFORCE_POLICY = "enforce_policy"
    REPORT = "report"


class DomainCategory(StrEnum):
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    CRYPTOMINING = "cryptomining"
    ADULT = "adult"
    GAMBLING = "gambling"
    BENIGN = "benign"


class PolicyAction(StrEnum):
    SINKHOLE = "sinkhole"
    NXDOMAIN = "nxdomain"
    REDIRECT = "redirect"
    LOG_ONLY = "log_only"
    ALLOW = "allow"


class DNSQueryRecord(BaseModel):
    """A DNS query record for firewall processing."""

    id: str = ""
    timestamp: str = ""
    source_ip: str = ""
    query_name: str = ""
    query_type: str = "A"
    response_code: str = "NOERROR"
    client_subnet: str = ""
    resolver: str = ""
    bytes_sent: int = 0


class DomainAnalysis(BaseModel):
    """Analysis result for a queried domain."""

    id: str = ""
    domain: str = ""
    category: DomainCategory = DomainCategory.BENIGN
    dga_score: float = 0.0
    entropy: float = 0.0
    age_days: int = -1
    is_newly_registered: bool = False
    alexa_rank: int = 0


class ReputationResult(BaseModel):
    """Reputation check result for a domain."""

    id: str = ""
    domain: str = ""
    reputation_score: float = 0.0
    threat_feeds_matched: int = 0
    feed_names: list[str] = Field(default_factory=list)
    is_blocklisted: bool = False
    confidence: float = 0.0


class TunnelingDetection(BaseModel):
    """DNS tunneling detection result."""

    id: str = ""
    source_ip: str = ""
    domain: str = ""
    subdomain_entropy: float = 0.0
    avg_query_length: float = 0.0
    query_frequency: float = 0.0
    payload_estimate_bytes: int = 0
    is_tunneling: bool = False
    confidence: float = 0.0


class PolicyEnforcement(BaseModel):
    """DNS policy enforcement action."""

    id: str = ""
    domain: str = ""
    action: PolicyAction = PolicyAction.LOG_ONLY
    reason: str = ""
    rpz_rule_id: str = ""
    sinkhole_ip: str = ""
    applied: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class DNSFirewallControllerState(BaseModel):
    """Main state for the DNS Firewall Controller agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: DFCStage = DFCStage.INGEST_QUERIES

    queries: list[dict[str, Any]] = Field(default_factory=list)
    domain_analyses: list[dict[str, Any]] = Field(default_factory=list)
    reputation_results: list[dict[str, Any]] = Field(default_factory=list)
    tunneling_detections: list[dict[str, Any]] = Field(default_factory=list)
    enforcements: list[dict[str, Any]] = Field(default_factory=list)

    report: str = ""
    total_queries: int = 0
    domains_blocked: int = 0
    tunneling_detected: int = 0

    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
