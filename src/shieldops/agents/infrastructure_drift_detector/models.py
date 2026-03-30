"""Infrastructure Drift Detector — state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IDDStage(StrEnum):
    """Stages in the drift detection workflow."""

    SCAN_INFRASTRUCTURE = "scan_infrastructure"
    COMPARE_BASELINE = "compare_baseline"
    DETECT_DRIFT = "detect_drift"
    CLASSIFY_CHANGES = "classify_changes"
    REMEDIATE_DRIFT = "remediate_drift"
    REPORT = "report"


class InfraLayer(StrEnum):
    """Infrastructure layers subject to drift."""

    COMPUTE = "compute"
    NETWORK = "network"
    STORAGE = "storage"
    SECURITY_GROUP = "security_group"
    IAM = "iam"
    DNS = "dns"


class DriftType(StrEnum):
    """Classification of detected drift."""

    UNAUTHORIZED = "unauthorized"
    CONFIGURATION = "configuration"
    VERSION = "version"
    MISSING = "missing"
    EXTRA = "extra"
    MODIFIED = "modified"


class InfrastructureDriftDetectorState(BaseModel):
    """Full state for the drift detection graph."""

    request_id: str = ""
    stage: IDDStage = IDDStage.SCAN_INFRASTRUCTURE
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
