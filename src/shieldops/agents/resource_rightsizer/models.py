"""Resource Rightsizer — state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RRStage(StrEnum):
    """Stages in the rightsizing workflow."""

    COLLECT_UTILIZATION = "collect_utilization"
    ANALYZE_PATTERNS = "analyze_patterns"
    IDENTIFY_OVERPROVISIONED = "identify_overprovisioned"
    RECOMMEND_SIZES = "recommend_sizes"
    VALIDATE_IMPACT = "validate_impact"
    REPORT = "report"


class ResourceCategory(StrEnum):
    """Resource categories for rightsizing."""

    EC2_INSTANCE = "ec2_instance"
    RDS_INSTANCE = "rds_instance"
    EKS_NODE = "eks_node"
    LAMBDA_FUNCTION = "lambda_function"
    EBS_VOLUME = "ebs_volume"
    CACHE_NODE = "cache_node"


class RightsizingAction(StrEnum):
    """Rightsizing action classification."""

    DOWNSIZE = "downsize"
    UPSIZE = "upsize"
    TERMINATE = "terminate"
    MIGRATE = "migrate"
    SCHEDULE = "schedule"
    KEEP = "keep"


class ResourceRightsizerState(BaseModel):
    """Full state for the rightsizing graph."""

    request_id: str = ""
    stage: RRStage = RRStage.COLLECT_UTILIZATION
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
