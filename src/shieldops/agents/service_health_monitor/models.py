"""State models for the Service Health Monitor Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SHMStage(StrEnum):
    """Stages of the service health monitoring workflow."""

    DISCOVER_SERVICES = "discover_services"
    CHECK_HEALTH = "check_health"
    ANALYZE_DEPENDENCIES = "analyze_dependencies"
    DETECT_DEGRADATION = "detect_degradation"
    TRIGGER_REMEDIATION = "trigger_remediation"
    REPORT = "report"


class HealthStatus(StrEnum):
    """Health status of a monitored service."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    MAINTENANCE = "maintenance"


class ServiceTier(StrEnum):
    """Criticality tier for a service."""

    TIER_1 = "tier_1"
    TIER_2 = "tier_2"
    TIER_3 = "tier_3"
    TIER_4 = "tier_4"


class ServiceEndpoint(BaseModel):
    """A discovered microservice endpoint."""

    id: str = ""
    name: str = ""
    url: str = ""
    tier: ServiceTier = ServiceTier.TIER_2
    owner: str = ""
    namespace: str = "default"
    health_endpoint: str = "/health"
    dependencies: list[str] = Field(default_factory=list)


class HealthCheck(BaseModel):
    """Result of a health check against a service."""

    service_id: str = ""
    service_name: str = ""
    status: HealthStatus = HealthStatus.UNKNOWN
    response_time_ms: float = 0.0
    error_rate_pct: float = 0.0
    cpu_usage_pct: float = 0.0
    memory_usage_pct: float = 0.0
    uptime_hours: float = 0.0
    last_checked: str = ""
    details: str = ""


class DependencyAnalysis(BaseModel):
    """Analysis of inter-service dependencies."""

    service_id: str = ""
    service_name: str = ""
    upstream: list[str] = Field(default_factory=list)
    downstream: list[str] = Field(default_factory=list)
    single_points_of_failure: list[str] = Field(
        default_factory=list,
    )
    cascade_risk: str = "low"
    impact_summary: str = ""


class DegradationEvent(BaseModel):
    """A detected service degradation event."""

    id: str = ""
    service_id: str = ""
    service_name: str = ""
    severity: str = "warning"
    degradation_type: str = ""
    metric_name: str = ""
    current_value: float = 0.0
    threshold_value: float = 0.0
    description: str = ""
    detected_at: str = ""


class RemediationAction(BaseModel):
    """An automated remediation action taken."""

    id: str = ""
    event_id: str = ""
    service_name: str = ""
    action_type: str = ""
    status: str = "pending"
    description: str = ""
    executed_at: str = ""
    result: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ServiceHealthMonitorState(BaseModel):
    """Full state for service health monitor workflow."""

    # Input
    tenant_id: str = ""

    # Discover services
    services: list[ServiceEndpoint] = Field(
        default_factory=list,
    )

    # Check health
    health_checks: list[HealthCheck] = Field(
        default_factory=list,
    )

    # Analyze dependencies
    dependency_analyses: list[DependencyAnalysis] = Field(
        default_factory=list,
    )

    # Detect degradation
    degradation_events: list[DegradationEvent] = Field(
        default_factory=list,
    )
    has_degradation: bool = False

    # Trigger remediation
    remediation_actions: list[RemediationAction] = Field(
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
