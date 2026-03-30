"""Tests for health_check_orchestrator."""

from __future__ import annotations

from shieldops.agents.health_check_orchestrator.models import (
    HCOStage,
    HealthCheckOrchestratorState,
    HealthMetric,
    ServiceStatus,
)


class TestEnums:
    def test_stage(self) -> None:
        assert HCOStage.DISCOVER_SERVICES == "discover_services"
        assert len(HCOStage) >= 3

    def test_service_status(self) -> None:
        assert ServiceStatus.HEALTHY == "healthy"
        assert len(ServiceStatus) >= 3

    def test_health_metric(self) -> None:
        assert HealthMetric.LATENCY == "latency"
        assert len(HealthMetric) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = HealthCheckOrchestratorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = HealthCheckOrchestratorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
