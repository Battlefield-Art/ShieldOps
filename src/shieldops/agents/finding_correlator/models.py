"""State models for the Finding Correlator Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CorrelatorStage(StrEnum):
    """Stages of the finding correlator workflow."""

    COLLECT_FINDINGS = "collect_findings"
    NORMALIZE_FINDINGS = "normalize_findings"
    DEDUPLICATE = "deduplicate"
    CORRELATE_RELATED = "correlate_related"
    PRIORITIZE = "prioritize"
    REPORT = "report"


class FindingSource(StrEnum):
    """Sources that produce security findings."""

    NETWORK_PENTEST = "network_pentest"
    WEB_APP_SCANNER = "web_app_scanner"
    CLOUD_PENTEST = "cloud_pentest"
    API_PENTEST = "api_pentest"
    CREDENTIAL_TESTER = "credential_tester"
    VULNERABILITY_INTELLIGENCE = "vulnerability_intelligence"
    EXPOSURE_MANAGEMENT = "exposure_management"


class CorrelationStrength(StrEnum):
    """Strength of correlation between findings."""

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    NONE = "none"


class RawFinding(BaseModel):
    """A finding before normalization."""

    id: str = ""
    source: str = ""
    source_type: FindingSource = FindingSource.NETWORK_PENTEST
    title: str = ""
    description: str = ""
    severity: str = ""
    asset: str = ""
    cvss_score: float = 0.0
    cve_id: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)


class NormalizedFinding(BaseModel):
    """A finding normalized to common schema."""

    id: str = ""
    original_ids: list[str] = Field(default_factory=list)
    source_type: FindingSource = FindingSource.NETWORK_PENTEST
    title: str = ""
    description: str = ""
    severity: str = ""
    asset: str = ""
    cvss_score: float = 0.0
    cve_id: str = ""
    fingerprint: str = ""


class DeduplicationResult(BaseModel):
    """Result of deduplication pass."""

    unique_findings: int = 0
    duplicates_removed: int = 0
    dedup_groups: list[dict[str, Any]] = Field(default_factory=list)


class CorrelationGroup(BaseModel):
    """A group of correlated findings."""

    id: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    strength: CorrelationStrength = CorrelationStrength.NONE
    correlation_reason: str = ""
    shared_asset: str = ""
    combined_risk: float = 0.0


class PrioritizedFinding(BaseModel):
    """A finding with final priority ranking."""

    finding_id: str = ""
    title: str = ""
    severity: str = ""
    priority_rank: int = 0
    risk_score: float = 0.0
    correlation_group_id: str = ""
    recommended_action: str = ""


class FindingCorrelatorState(BaseModel):
    """Full state for the finding correlator workflow."""

    # Input
    tenant_id: str = ""
    request_id: str = ""

    # Pipeline data
    raw_findings: list[RawFinding] = Field(default_factory=list)
    normalized: list[NormalizedFinding] = Field(default_factory=list)
    deduplicated: list[NormalizedFinding] = Field(default_factory=list)
    correlations: list[CorrelationGroup] = Field(default_factory=list)
    prioritized: list[PrioritizedFinding] = Field(default_factory=list)

    # Metrics
    duplicates_removed: int = 0
    correlation_groups: int = 0

    # Workflow tracking
    current_stage: CorrelatorStage = CorrelatorStage.COLLECT_FINDINGS
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_duration_ms: int = 0
