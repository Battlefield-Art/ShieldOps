"""Defense In Depth Auditor Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AuditStage(StrEnum):
    MAP_LAYERS = "map_layers"
    ASSESS_CONTROLS = "assess_controls"
    IDENTIFY_GAPS = "identify_gaps"
    TEST_RESILIENCE = "test_resilience"
    RECOMMEND = "recommend"
    REPORT = "report"


class DefenseLayer(StrEnum):
    PERIMETER = "perimeter"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    APPLICATION = "application"
    DATA = "data"
    USER = "user"


class ControlEffectiveness(StrEnum):
    STRONG = "strong"
    ADEQUATE = "adequate"
    WEAK = "weak"
    MISSING = "missing"
    COMPENSATING = "compensating"


class DefenseInDepthAuditorState(BaseModel):
    request_id: str = ""
    stage: AuditStage = AuditStage.MAP_LAYERS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
