"""Threat Surface Minimizer Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MinimizationStage(StrEnum):
    DISCOVER_SURFACE = "discover_surface"
    MAP_EXPOSURE = "map_exposure"
    PRIORITIZE_RISKS = "prioritize_risks"
    RECOMMEND_REDUCTION = "recommend_reduction"
    VALIDATE = "validate"
    REPORT = "report"


class SurfaceType(StrEnum):
    EXTERNAL_IP = "external_ip"
    OPEN_PORT = "open_port"
    PUBLIC_API = "public_api"
    EXPOSED_SERVICE = "exposed_service"
    SHADOW_IT = "shadow_it"
    STALE_ASSET = "stale_asset"


class ExposureLevel(StrEnum):
    INTERNET_FACING = "internet_facing"
    DMZ = "dmz"
    INTERNAL = "internal"
    ISOLATED = "isolated"
    AIR_GAPPED = "air_gapped"


class ThreatSurfaceMinimizerState(BaseModel):
    request_id: str = ""
    stage: MinimizationStage = MinimizationStage.DISCOVER_SURFACE
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
