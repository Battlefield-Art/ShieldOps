"""Service Dependency Mapper Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SDMStage(StrEnum):
    DISCOVER_SERVICES = "discover_services"
    TRACE_CONNECTIONS = "trace_connections"
    MAP_DEPENDENCIES = "map_dependencies"
    DETECT_CYCLES = "detect_cycles"
    ASSESS_RESILIENCE = "assess_resilience"
    REPORT = "report"


class ConnectionType(StrEnum):
    SYNCHRONOUS = "synchronous"
    ASYNCHRONOUS = "asynchronous"
    EVENT_DRIVEN = "event_driven"
    SHARED_DATA = "shared_data"
    HEALTH_CHECK = "health_check"
    DEPLOYMENT = "deployment"


class ResilienceLevel(StrEnum):
    RESILIENT = "resilient"
    ADEQUATE = "adequate"
    FRAGILE = "fragile"
    CRITICAL_PATH = "critical_path"
    SINGLE_POINT_OF_FAILURE = "single_point_of_failure"


class ServiceDependencyMapperState(BaseModel):
    request_id: str = ""
    stage: SDMStage = SDMStage.DISCOVER_SERVICES
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
