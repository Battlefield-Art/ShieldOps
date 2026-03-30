"""Unit tests for service_health_monitor agent models."""

from __future__ import annotations

from shieldops.agents.service_health_monitor.models import (
    HealthStatus,
    ServiceHealthMonitorState,
    ServiceTier,
    SHMStage,
)


class TestEnums:
    def test_shm_stage_values(self) -> None:
        assert SHMStage.DISCOVER_SERVICES == "discover_services"
        assert SHMStage.CHECK_HEALTH == "check_health"
        assert SHMStage.DETECT_DEGRADATION == "detect_degradation"
        assert SHMStage.REPORT == "report"

    def test_health_status_values(self) -> None:
        assert HealthStatus.HEALTHY == "healthy"
        assert HealthStatus.DEGRADED == "degraded"
        assert HealthStatus.UNHEALTHY == "unhealthy"
        assert HealthStatus.MAINTENANCE == "maintenance"

    def test_service_tier_values(self) -> None:
        assert ServiceTier.TIER_1 == "tier_1"
        assert ServiceTier.TIER_2 == "tier_2"
        assert ServiceTier.TIER_3 == "tier_3"


class TestState:
    def test_default_state(self) -> None:
        state = ServiceHealthMonitorState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.stage == SHMStage.DISCOVER_SERVICES
        assert state.error == ""

    def test_state_with_values(self) -> None:
        state = ServiceHealthMonitorState(
            request_id="req-001",
            tenant_id="t-001",
            stage=SHMStage.CHECK_HEALTH,
        )
        assert state.request_id == "req-001"
        assert state.stage == SHMStage.CHECK_HEALTH
