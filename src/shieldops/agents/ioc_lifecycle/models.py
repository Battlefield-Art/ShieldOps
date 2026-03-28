"""State models for IOC Lifecycle Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IOCStage(StrEnum):
    """Stages in the IOC lifecycle workflow."""

    COLLECT = "collect"
    VALIDATE = "validate"
    ENRICH = "enrich"
    CLASSIFY = "classify"
    AGE_CHECK = "age_check"
    REPORT = "report"


class IOCType(StrEnum):
    """Types of indicators of compromise."""

    IP = "ip"
    DOMAIN = "domain"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    URL = "url"
    EMAIL = "email"
    CVE = "cve"


class IOCStatus(StrEnum):
    """Lifecycle status of an IOC."""

    ACTIVE = "active"
    AGED = "aged"
    EXPIRED = "expired"
    FALSE_POSITIVE = "false_positive"
    RETIRED = "retired"


class IOCRecord(BaseModel):
    """A single indicator of compromise record."""

    id: str = ""
    ioc_type: IOCType = IOCType.IP
    value: str = ""
    source: str = ""
    status: IOCStatus = IOCStatus.ACTIVE
    confidence: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class IOCEnrichment(BaseModel):
    """Enrichment data for an IOC."""

    ioc_id: str = ""
    threat_score: float = 0.0
    malware_families: list[str] = Field(default_factory=list)
    geo_location: str = ""
    asn: str = ""
    whois_info: str = ""
    related_campaigns: list[str] = Field(default_factory=list)
    enrichment_source: str = ""
    enriched_at: float = 0.0


class IOCClassification(BaseModel):
    """Classification result for an IOC."""

    ioc_id: str = ""
    severity: str = "medium"
    category: str = ""
    kill_chain_phase: str = ""
    mitre_tactics: list[str] = Field(default_factory=list)
    is_false_positive: bool = False
    fp_reason: str = ""
    classified_at: float = 0.0


class IOCLifecycleState(BaseModel):
    """Full state for IOC Lifecycle Agent."""

    request_id: str = ""
    stage: IOCStage = IOCStage.COLLECT
    tenant_id: str = ""
    sources: list[str] = Field(default_factory=list)
    iocs: list[IOCRecord] = Field(default_factory=list)
    enrichments: list[IOCEnrichment] = Field(default_factory=list)
    classifications: list[IOCClassification] = Field(
        default_factory=list,
    )
    false_positive_count: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_start: float = 0.0
