"""State models for the Multi-Cloud Posture Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class PostureStage(StrEnum):
    """Workflow stages for multi-cloud posture management."""

    SCAN_CLOUDS = "scan_clouds"
    NORMALIZE_FINDINGS = "normalize_findings"
    COMPARE_POSTURE = "compare_posture"
    DETECT_GAPS = "detect_gaps"
    RECOMMEND = "recommend"
    REPORT = "report"


class CloudProvider(StrEnum):
    """Supported cloud providers."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    ON_PREM = "on_prem"


class FindingSeverity(StrEnum):
    """Severity levels for posture findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ── Domain Models ─────────────────────────────────────


class CloudScanResult(BaseModel):
    """Scan result from a single cloud provider."""

    scan_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    region: str = ""
    findings_count: int = 0
    critical_count: int = 0
    score: float = 0.0
    scanned_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class NormalizedFinding(BaseModel):
    """A cloud finding normalized to a common schema."""

    finding_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    severity: FindingSeverity = FindingSeverity.MEDIUM
    category: str = ""
    resource: str = ""
    description: str = ""
    benchmark: str = ""
    remediation: str = ""


class PostureComparison(BaseModel):
    """Cross-cloud posture comparison result."""

    category: str = ""
    aws_score: float = 0.0
    gcp_score: float = 0.0
    azure_score: float = 0.0
    weakest_provider: str = ""
    gap: float = 0.0


class SecurityGap(BaseModel):
    """A detected gap in cross-cloud security posture."""

    gap_id: str = ""
    category: str = ""
    affected_providers: list[str] = Field(default_factory=list)
    severity: FindingSeverity = FindingSeverity.MEDIUM
    description: str = ""
    impact: str = ""


class PostureRecommendation(BaseModel):
    """Recommendation for improving cloud posture."""

    rec_id: str = ""
    provider: str = ""
    category: str = ""
    priority: str = "medium"
    action: str = ""
    effort: str = "medium"
    score_improvement: float = 0.0


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the posture workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class MultiCloudPostureState(BaseModel):
    """Full state for the Multi-Cloud Posture workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: PostureStage = PostureStage.SCAN_CLOUDS
    posture_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Scan
    cloud_scans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_findings: int = 0

    # Normalize
    normalized_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Compare
    posture_comparisons: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    overall_score: float = 0.0

    # Gaps
    security_gaps: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    critical_gaps: int = 0

    # Recommendations
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
