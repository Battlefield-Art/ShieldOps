"""Micro Segmentation Planner Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PlanningStage(StrEnum):
    MAP_TRAFFIC = "map_traffic"
    IDENTIFY_SEGMENTS = "identify_segments"
    DEFINE_POLICIES = "define_policies"
    SIMULATE = "simulate"
    VALIDATE = "validate"
    REPORT = "report"


class SegmentType(StrEnum):
    APPLICATION = "application"
    ENVIRONMENT = "environment"
    DATA_SENSITIVITY = "data_sensitivity"
    COMPLIANCE = "compliance"
    BUSINESS_UNIT = "business_unit"
    CUSTOM = "custom"


class PolicyAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"
    ALERT = "alert"
    QUARANTINE = "quarantine"
    REDIRECT = "redirect"


class MicroSegmentationPlannerState(BaseModel):
    request_id: str = ""
    stage: PlanningStage = PlanningStage.MAP_TRAFFIC
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
