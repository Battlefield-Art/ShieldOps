"""Wire LicenseGuard counter to a real agent registry — TDD tests (#2)."""

from __future__ import annotations

from datetime import UTC

import pytest

from shieldops.licensing.registry_counter import (
    AgentRegistryCounter,
    InMemoryAgentRegistry,
)


@pytest.fixture()
def registry() -> InMemoryAgentRegistry:
    return InMemoryAgentRegistry()


@pytest.fixture()
def counter(registry: InMemoryAgentRegistry) -> AgentRegistryCounter:
    return AgentRegistryCounter(registry=registry)


class TestRegistryCounter:
    def test_empty_registry_counts_zero(self, counter: AgentRegistryCounter) -> None:
        assert counter() == 0

    def test_started_agent_counts_one(
        self, counter: AgentRegistryCounter, registry: InMemoryAgentRegistry
    ) -> None:
        registry.set_status("investigation", "started")
        assert counter() == 1

    def test_idle_agent_does_not_count(
        self, counter: AgentRegistryCounter, registry: InMemoryAgentRegistry
    ) -> None:
        registry.set_status("investigation", "idle")
        registry.set_status("remediation", "started")
        assert counter() == 1

    def test_failed_agent_does_not_count(
        self, counter: AgentRegistryCounter, registry: InMemoryAgentRegistry
    ) -> None:
        registry.set_status("investigation", "failed")
        registry.set_status("remediation", "started")
        assert counter() == 1

    def test_stopping_an_agent_decrements_count(
        self, counter: AgentRegistryCounter, registry: InMemoryAgentRegistry
    ) -> None:
        registry.set_status("a", "started")
        registry.set_status("b", "started")
        assert counter() == 2
        registry.set_status("a", "idle")
        assert counter() == 1


class TestStartupHookIntegration:
    def test_install_registry_counter_wires_into_guard(self) -> None:
        from datetime import datetime, timedelta

        from shieldops.licensing import startup_hook
        from shieldops.licensing.guard import LicenseExceededError, LicenseGuard
        from shieldops.licensing.models import License, LicenseTier
        from shieldops.licensing.registry_counter import (
            install_registry_counter,
        )

        registry = InMemoryAgentRegistry()
        license = License(
            org_id="test-org",
            tier=LicenseTier.STARTER,
            agent_limit=2,
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(days=365),
            signature="sig",
        )
        guard = LicenseGuard(license=license)
        install_registry_counter(guard=guard, registry=registry)
        startup_hook.set_guard(guard)

        try:
            registry.set_status("a", "started")
            registry.set_status("b", "started")
            # 3rd agent should be denied because the registry already shows 2
            with pytest.raises(LicenseExceededError):
                startup_hook.check_startup("c")
        finally:
            startup_hook.set_guard(None)
