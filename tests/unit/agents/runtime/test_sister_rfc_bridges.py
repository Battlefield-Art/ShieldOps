"""Contract tests for the AgentRuntime sister-RFC bridges — #247 PR-2.

See ghantakiran/ShieldOps#247. These adapters bridge the pure runtime
ports (``LicenseManagerPort``, ``EvolutionStorePort``, ``WSHubPort``)
to the real sister-RFC subsystems (#244 licensing, #246 evolution,
#242 WS hub) via their composition roots.

Each bridge is tested in isolation against the in-memory sister
adapters so the contracts lock the translation, not the underlying
subsystem behavior (that's covered by each sister RFC's own tests).

Invariants locked:

1. **Missing subsystem is a warning, not a crash** — all three bridges
   consult the composition root lazily and fall back safely when
   nothing is installed.
2. **Broken subsystem cannot crash the runtime** — if the underlying
   subsystem raises, the bridge swallows + logs.
3. **Translation is correct** — each bridge maps the runtime's port
   vocabulary to the sister RFC's vocabulary without losing fields.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from shieldops.agents.runtime.adapters.sister_rfc_bridges import (
    EvolutionStoreBridge,
    LicenseManagerBridge,
    WSHubBridge,
)
from shieldops.api.ws.composition import (
    build_in_memory_hub,
    set_ws_hub,
    use_test_ws_hub,
)
from shieldops.api.ws.core import Principal
from shieldops.licensing.composition import set_license_manager, use_test_license
from shieldops.licensing.manager import LicenseManager
from shieldops.licensing.models import License
from shieldops.utils.evolution.composition import (
    set_evolution_store,
    use_test_evolution,
)


@pytest.fixture(autouse=True)
def _isolate_subsystems():
    set_license_manager(None)
    set_evolution_store(None)
    set_ws_hub(None)
    yield
    set_license_manager(None)
    set_evolution_store(None)
    set_ws_hub(None)


# ---------------------------------------------------------------------------
# LicenseManagerBridge
# ---------------------------------------------------------------------------


def _unlimited_manager() -> LicenseManager:
    return LicenseManager.unlimited()


def _zero_limit_manager_full() -> LicenseManager:
    now = datetime.now(UTC)
    lic = License(
        org_id="test-org",
        tier="starter",
        agent_limit=1,
        issued_at=now,
        expires_at=now + timedelta(days=365),
        signature="test-sig",
    )
    mgr = LicenseManager(license=lic, grace_days=30)
    mgr.admit("seed-agent")  # exhaust the limit of 1
    return mgr


class TestLicenseManagerBridge:
    def test_check_returns_true_when_manager_missing(self) -> None:
        bridge = LicenseManagerBridge()
        assert bridge.check("agent-a", "tenant-a") is True

    def test_check_returns_true_for_unlimited_manager(self) -> None:
        bridge = LicenseManagerBridge()
        with use_test_license(_unlimited_manager()):
            assert bridge.check("agent-a", "tenant-a") is True

    def test_check_returns_false_when_manager_is_full(self) -> None:
        bridge = LicenseManagerBridge()
        with use_test_license(_zero_limit_manager_full()):
            assert bridge.check("agent-new", "tenant-a") is False

    def test_check_is_readonly_no_slot_reserved(self) -> None:
        """After a successful check, the manager's running count must
        not have grown — the port contract is an admissibility query,
        not a reservation."""
        bridge = LicenseManagerBridge()
        mgr = _unlimited_manager()
        with use_test_license(mgr):
            before = len(mgr._running)  # type: ignore[attr-defined]
            assert bridge.check("agent-a", "tenant-a") is True
            after = len(mgr._running)  # type: ignore[attr-defined]
            assert after == before

    def test_broken_manager_fails_open(self) -> None:
        """A manager that raises on admit → bridge logs and returns True
        so the runtime stays up."""

        class _BrokenManager:
            def admit(self, _name: str) -> None:
                raise RuntimeError("manager subsystem down")

        set_license_manager(_BrokenManager())  # type: ignore[arg-type]
        bridge = LicenseManagerBridge()
        assert bridge.check("agent-a", "tenant-a") is True


# ---------------------------------------------------------------------------
# EvolutionStoreBridge
# ---------------------------------------------------------------------------


class TestEvolutionStoreBridge:
    @pytest.mark.asyncio
    async def test_missing_store_is_a_noop(self) -> None:
        bridge = EvolutionStoreBridge()
        # Must not raise.
        await bridge.record_run(
            agent_name="agent-a",
            tenant_id="tenant-a",
            success=True,
            latency_ms=100.0,
            node_count=3,
        )

    @pytest.mark.asyncio
    async def test_single_run_produces_single_event(self) -> None:
        bridge = EvolutionStoreBridge()
        with use_test_evolution() as store:
            await bridge.record_run(
                agent_name="agent-a",
                tenant_id="tenant-a",
                success=True,
                latency_ms=250.0,
                node_count=5,
            )
            events = [
                e for e in store.learning_events(tenant_id="tenant-a") if e.agent_id == "agent-a"
            ]
            assert len(events) == 1
            obs = events[0].payload["observation"]
            assert obs["accuracy"] == 1.0

    @pytest.mark.asyncio
    async def test_failure_maps_to_zero_accuracy(self) -> None:
        bridge = EvolutionStoreBridge()
        with use_test_evolution() as store:
            await bridge.record_run(
                agent_name="agent-a",
                tenant_id="tenant-a",
                success=False,
                latency_ms=50.0,
                node_count=1,
            )
            events = [
                e for e in store.learning_events(tenant_id="tenant-a") if e.agent_id == "agent-a"
            ]
            assert events[0].payload["observation"]["accuracy"] == 0.0

    @pytest.mark.asyncio
    async def test_empty_tenant_defaults_to_default(self) -> None:
        bridge = EvolutionStoreBridge()
        with use_test_evolution() as store:
            await bridge.record_run(
                agent_name="agent-a",
                tenant_id="",
                success=True,
                latency_ms=100.0,
                node_count=1,
            )
            events = [
                e for e in store.learning_events(tenant_id="default") if e.agent_id == "agent-a"
            ]
            assert len(events) == 1

    @pytest.mark.asyncio
    async def test_broken_store_does_not_crash(self) -> None:
        class _BrokenStore:
            def for_agent(self, *_a: Any, **_k: Any) -> Any:
                raise RuntimeError("store subsystem down")

        set_evolution_store(_BrokenStore())  # type: ignore[arg-type]
        bridge = EvolutionStoreBridge()
        # Must not raise.
        await bridge.record_run(
            agent_name="agent-a",
            tenant_id="tenant-a",
            success=True,
            latency_ms=100.0,
            node_count=1,
        )


# ---------------------------------------------------------------------------
# WSHubBridge
# ---------------------------------------------------------------------------


class TestWSHubBridge:
    @pytest.mark.asyncio
    async def test_missing_hub_is_a_noop(self) -> None:
        bridge = WSHubBridge()
        await bridge.publish("tenant-a:agents", {"kind": "agent.started", "agent": "a"})

    @pytest.mark.asyncio
    async def test_publish_reaches_installed_hub(self) -> None:
        """When a hub is installed + a subscription exists, the bridge's
        publish call must reach the subscriber's transport."""
        import asyncio

        hub = build_in_memory_hub(
            tokens={"t1": Principal(tenant_id="tenant-a", user_id="u1")},
        )
        with use_test_ws_hub(hub):
            hub.transport.register("c1")
            await hub.attach(conn_id="c1", channel="tenant-a:agents", token="t1")
            bridge = WSHubBridge()
            await bridge.publish(
                "tenant-a:agents",
                {"kind": "agent.started", "agent_name": "a", "run_id": "r1"},
            )
            # Let the hub drain the queue to the transport.
            await asyncio.sleep(0)
            await asyncio.sleep(0)

            frames = hub.transport.sent("c1")
            kinds = [f.get("kind") for f in frames]
            assert "agent.started" in kinds

            await hub.detach("c1")

    @pytest.mark.asyncio
    async def test_event_without_kind_defaults_to_agent_event(self) -> None:
        import asyncio

        hub = build_in_memory_hub(
            tokens={"t1": Principal(tenant_id="tenant-a", user_id="u1")},
        )
        with use_test_ws_hub(hub):
            hub.transport.register("c2")
            await hub.attach(conn_id="c2", channel="tenant-a:agents", token="t1")
            bridge = WSHubBridge()
            # No kind / type field in the dict — bridge picks the default.
            await bridge.publish("tenant-a:agents", {"payload": 42})
            await asyncio.sleep(0)
            await asyncio.sleep(0)

            frames = hub.transport.sent("c2")
            assert any(f.get("kind") == "agent.event" for f in frames)

            await hub.detach("c2")
