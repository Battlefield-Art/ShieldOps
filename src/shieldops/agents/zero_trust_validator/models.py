"""Zero Trust Validator Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ValidationStage(StrEnum):
    INVENTORY_ASSETS = "inventory_assets"
    CHECK_IDENTITY = "check_identity"
    VERIFY_ACCESS = "verify_access"
    INSPECT_TRAFFIC = "inspect_traffic"
    ASSESS_POSTURE = "assess_posture"
    REPORT = "report"


class ZTPillar(StrEnum):
    IDENTITY = "identity"
    DEVICES = "devices"
    NETWORK = "network"
    APPLICATIONS = "applications"
    DATA = "data"
    VISIBILITY = "visibility"


class MaturityLevel(StrEnum):
    TRADITIONAL = "traditional"
    INITIAL = "initial"
    ADVANCED = "advanced"
    OPTIMAL = "optimal"


class ZeroTrustValidatorState(BaseModel):
    request_id: str = ""
    stage: ValidationStage = ValidationStage.INVENTORY_ASSETS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
