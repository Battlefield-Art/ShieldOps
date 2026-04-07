"""Contract tests for the WS Hub composition root — #242 PR-2.

See ghantakiran/ShieldOps#242. These tests lock the same
setter/getter/use_test invariants as the sister composition roots
(:mod:`shieldops.api.policy.composition`,
:mod:`shieldops.utils.evolution.composition`,
:mod:`shieldops.licensing.composition`), so the FastAPI layer can
reach the single shared hub via ``Depends(get_ws_hub)``.
"""

from __future__ import annotations

import pytest

from shieldops.api.ws.composition import (
    build_in_memory_hub,
    get_ws_hub,
    set_ws_hub,
    use_test_ws_hub,
)
from shieldops.api.ws.core import Event, Hub, HubConfig, Principal


@pytest.fixture(autouse=True)
def _isolate_hub():
    set_ws_hub(None)
    yield
    set_ws_hub(None)


class TestSetterGetter:
    def test_get_raises_when_unset(self) -> None:
        with pytest.raises(RuntimeError, match="No WebSocket Hub installed"):
            get_ws_hub()

    def test_set_then_get_returns_same_instance(self) -> None:
        hub = build_in_memory_hub()
        set_ws_hub(hub)
        assert get_ws_hub() is hub

    def test_set_none_clears_installed_hub(self) -> None:
        set_ws_hub(build_in_memory_hub())
        set_ws_hub(None)
        with pytest.raises(RuntimeError):
            get_ws_hub()


class TestBuildInMemoryHub:
    def test_defaults_produce_a_fully_wired_hub(self) -> None:
        hub = build_in_memory_hub()
        assert isinstance(hub, Hub)
        # All ports must be non-None on the returned hub.
        assert hub.transport is not None
        assert hub.buffer is not None
        assert hub.auth is not None
        assert hub.clock is not None
        assert hub.log is not None
        assert hub.tracer is not None

    def test_hub_config_override_is_passed_through(self) -> None:
        cfg = HubConfig(queue_max=32, replay_max_events=10)
        hub = build_in_memory_hub(config=cfg)
        assert hub.config is cfg

    def test_start_ts_seeds_clock(self) -> None:
        hub = build_in_memory_hub(start_ts=123.0)
        # ManualClock.timestamp() returns the raw float seed; .now()
        # returns the corresponding UTC datetime.
        assert hub.clock.timestamp() == 123.0

    @pytest.mark.asyncio
    async def test_hub_accepts_provided_tokens_for_attach(self) -> None:
        """Tokens passed to build_in_memory_hub wire the StaticTokenAuthenticator."""
        tokens = {"t1": Principal(tenant_id="org-a", user_id="u1")}
        hub = build_in_memory_hub(tokens=tokens)

        # attach should succeed for the configured token+channel.
        await hub.attach(conn_id="c1", channel="org-a:ch1", token="t1")
        # publish + detach round-trip works.
        await hub.publish("org-a:ch1", Event(kind="hello", data={"x": 1}))
        await hub.detach("c1")


class TestUseTestContextManager:
    def test_swaps_hub_and_restores_on_exit(self) -> None:
        outer = build_in_memory_hub()
        set_ws_hub(outer)

        with use_test_ws_hub() as inner:
            assert get_ws_hub() is inner
            assert inner is not outer

        assert get_ws_hub() is outer

    def test_swaps_hub_and_restores_on_exception(self) -> None:
        outer = build_in_memory_hub()
        set_ws_hub(outer)

        with pytest.raises(ValueError, match="boom"), use_test_ws_hub():
            raise ValueError("boom")

        assert get_ws_hub() is outer

    def test_accepts_an_explicit_hub(self) -> None:
        explicit = build_in_memory_hub()
        with use_test_ws_hub(explicit) as yielded:
            assert yielded is explicit
            assert get_ws_hub() is explicit

    def test_nested_use_test_ws_hub_blocks(self) -> None:
        a = build_in_memory_hub()
        b = build_in_memory_hub()
        with use_test_ws_hub(a):
            assert get_ws_hub() is a
            with use_test_ws_hub(b):
                assert get_ws_hub() is b
            assert get_ws_hub() is a
