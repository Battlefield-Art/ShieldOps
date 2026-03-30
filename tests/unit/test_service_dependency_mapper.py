"""Tests for service_dependency_mapper."""

from __future__ import annotations

from shieldops.agents.service_dependency_mapper.models import (
    ConnectionType,
    ResilienceLevel,
    SDMStage,
    ServiceDependencyMapperState,
)


class TestEnums:
    def test_stage(self) -> None:
        assert SDMStage.DISCOVER_SERVICES == "discover_services"
        assert len(SDMStage) >= 3

    def test_connection_type(self) -> None:
        assert ConnectionType.SYNCHRONOUS == "synchronous"
        assert len(ConnectionType) >= 3

    def test_resilience_level(self) -> None:
        assert ResilienceLevel.RESILIENT == "resilient"
        assert len(ResilienceLevel) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ServiceDependencyMapperState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ServiceDependencyMapperState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
