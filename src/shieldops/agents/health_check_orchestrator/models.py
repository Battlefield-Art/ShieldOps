"""Health Check Orchestrator Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class HCOStage(StrEnum):
    DISCOVER_SERVICES = "discover_services"
    PROBE_ENDPOINTS = "probe_endpoints"
    ASSESS_HEALTH = "assess_health"
    CORRELATE_ISSUES = "correlate_issues"
    TRIGGER_REMEDIATION = "trigger_remediation"
    REPORT = "report"


class ServiceStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNREACHABLE = "unreachable"
    MAINTENANCE = "maintenance"
    UNKNOWN = "unknown"


class HealthMetric(StrEnum):
    LATENCY = "latency"
    ERROR_RATE = "error_rate"
    THROUGHPUT = "throughput"
    SATURATION = "saturation"
    AVAILABILITY = "availability"
    CORRECTNESS = "correctness"


class HealthCheckOrchestratorState(BaseModel):
    request_id: str = ""
    stage: HCOStage = HCOStage.DISCOVER_SERVICES
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
