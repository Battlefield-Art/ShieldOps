"""State models for the Cloud Resource Tagger Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TagStage(StrEnum):
    """Stages of the cloud resource tagging workflow."""

    SCAN_RESOURCES = "scan_resources"
    ANALYZE_METADATA = "analyze_metadata"
    GENERATE_TAGS = "generate_tags"
    VALIDATE_COMPLIANCE = "validate_compliance"
    APPLY_TAGS = "apply_tags"
    REPORT = "report"


class ComplianceLevel(StrEnum):
    """Tag compliance levels."""

    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    EXEMPT = "exempt"
    UNKNOWN = "unknown"


class CloudProvider(StrEnum):
    """Supported cloud providers."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    KUBERNETES = "kubernetes"
    MULTI_CLOUD = "multi_cloud"


class CloudResource(BaseModel):
    """A discovered cloud resource."""

    id: str = ""
    name: str = ""
    resource_type: str = ""
    provider: CloudProvider = CloudProvider.AWS
    region: str = ""
    existing_tags: dict[str, str] = Field(default_factory=dict)
    missing_tags: list[str] = Field(default_factory=list)
    compliance: ComplianceLevel = ComplianceLevel.UNKNOWN


class TagRecommendation(BaseModel):
    """A generated tag recommendation."""

    id: str = ""
    resource_id: str = ""
    tag_key: str = ""
    tag_value: str = ""
    source: str = "auto"
    confidence: float = 0.0


class TagPolicy(BaseModel):
    """A tag compliance policy."""

    id: str = ""
    name: str = ""
    required_keys: list[str] = Field(default_factory=list)
    allowed_values: dict[str, list[str]] = Field(default_factory=dict)
    scope: str = "all"


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: int = 0
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudResourceTaggerState(BaseModel):
    """Full state of a cloud resource tagging workflow."""

    # Identity
    request_id: str = ""
    stage: TagStage = TagStage.SCAN_RESOURCES
    tenant_id: str = ""

    # Data
    resources: list[dict[str, Any]] = Field(default_factory=list)
    metadata_analyses: list[dict[str, Any]] = Field(default_factory=list)
    tag_recommendations: list[dict[str, Any]] = Field(default_factory=list)
    compliance_results: list[dict[str, Any]] = Field(default_factory=list)
    applied_tags: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    total_resources: int = 0
    untagged_count: int = 0
    compliance_pct: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
