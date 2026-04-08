"""Tests for shieldops.api.routes.agent_ws — WebSocket handler for agent task updates.

RFC #242 PR-3 (#257) — the route was migrated off the local
``ConnectionManager`` onto the WebSocket Hub. ``notify_step_update`` now
publishes to the topic ``agent_task:<task_id>`` via the installed Hub.
The legacy ``ConnectionManager`` and module-level ``manager`` singleton
are gone; these tests now exercise the Hub-backed path end-to-end via
:func:`use_test_ws_hub`.
"""

from __future__ import annotations

import pytest

from shieldops.api.routes.agent_ws import notify_step_update
from shieldops.api.ws.adapters import (
    InMemoryBuffer,
    InMemoryTransport,
    ManualClock,
    NullLogger,
    NullTracer,
    StaticTokenAuthenticator,
)
from shieldops.api.ws.composition import set_ws_hub, use_test_ws_hub
from shieldops.api.ws.core import Hub, HubConfig, Principal


@pytest.fixture(autouse=True)
def _isolate_hub():
    set_ws_hub(None)
    yield
    set_ws_hub(None)


def _build_hub() -> tuple[Hub, InMemoryTransport]:
    transport = InMemoryTransport()
    hub = Hub(
        transport=transport,
        buffer=InMemoryBuffer(),
        auth=StaticTokenAuthenticator(tokens={"tok": Principal(tenant_id="t")}),
        clock=ManualClock(start=0.0),
        log=NullLogger(),
        tracer=NullTracer(),
        config=HubConfig(queue_max=64, replay_max_events=100),
    )
    return hub, transport


async def _attach_subscriber(hub: Hub, transport: InMemoryTransport, task_id: str) -> str:
    conn_id = f"client-{task_id}"
    transport.register(conn_id)
    await hub.attach(
        conn_id=conn_id,
        channel=f"agent_task:{task_id}",
        token="tok",
        since_id=None,
    )
    return conn_id


async def _drain_event_loop() -> None:
    import asyncio

    await asyncio.sleep(0)
    await asyncio.sleep(0)


# ---------------------------------------------------------------------------
# notify_step_update — publishes to the Hub
# ---------------------------------------------------------------------------


class TestNotifyStepUpdate:
    @pytest.mark.asyncio
    async def test_step_update_event_kind(self) -> None:
        hub, transport = _build_hub()
        with use_test_ws_hub(hub):
            conn = await _attach_subscriber(hub, transport, "t1")
            await notify_step_update(task_id="t1", step_id="s1", status="running")
            await _drain_event_loop()
            sent = transport.sent(conn)
            assert len(sent) == 1
            envelope = sent[0]
            assert envelope["kind"] == "step_update"
            assert envelope["data"]["status"] == "running"
            assert envelope["data"]["step_id"] == "s1"
            assert "timestamp" in envelope["data"]
            await hub.detach(conn)

    @pytest.mark.asyncio
    async def test_complete_event_kind(self) -> None:
        hub, transport = _build_hub()
        with use_test_ws_hub(hub):
            conn = await _attach_subscriber(hub, transport, "t1")
            await notify_step_update(task_id="t1", step_id="s1", status="complete")
            await _drain_event_loop()
            envelope = transport.sent(conn)[0]
            assert envelope["kind"] == "task_complete"
            await hub.detach(conn)

    @pytest.mark.asyncio
    async def test_approval_required_event_kind(self) -> None:
        hub, transport = _build_hub()
        with use_test_ws_hub(hub):
            conn = await _attach_subscriber(hub, transport, "t1")
            await notify_step_update(task_id="t1", step_id="s1", status="approval_required")
            await _drain_event_loop()
            assert transport.sent(conn)[0]["kind"] == "approval_required"
            await hub.detach(conn)

    @pytest.mark.asyncio
    async def test_error_event_kind_includes_error(self) -> None:
        hub, transport = _build_hub()
        with use_test_ws_hub(hub):
            conn = await _attach_subscriber(hub, transport, "t1")
            await notify_step_update(task_id="t1", step_id="s1", status="error", error="OOM killed")
            await _drain_event_loop()
            envelope = transport.sent(conn)[0]
            assert envelope["kind"] == "error"
            assert envelope["data"]["error"] == "OOM killed"
            await hub.detach(conn)

    @pytest.mark.asyncio
    async def test_unknown_status_defaults_to_step_update(self) -> None:
        hub, transport = _build_hub()
        with use_test_ws_hub(hub):
            conn = await _attach_subscriber(hub, transport, "t1")
            await notify_step_update(task_id="t1", step_id="s1", status="initializing")
            await _drain_event_loop()
            assert transport.sent(conn)[0]["kind"] == "step_update"
            await hub.detach(conn)

    @pytest.mark.asyncio
    async def test_result_included_when_provided(self) -> None:
        hub, transport = _build_hub()
        with use_test_ws_hub(hub):
            conn = await _attach_subscriber(hub, transport, "t1")
            await notify_step_update(
                task_id="t1",
                step_id="s1",
                status="complete",
                result={"finding": "root cause identified"},
            )
            await _drain_event_loop()
            data = transport.sent(conn)[0]["data"]
            assert data["result"] == {"finding": "root cause identified"}
            await hub.detach(conn)

    @pytest.mark.asyncio
    async def test_result_omitted_when_none(self) -> None:
        hub, transport = _build_hub()
        with use_test_ws_hub(hub):
            conn = await _attach_subscriber(hub, transport, "t1")
            await notify_step_update(task_id="t1", step_id="s1", status="running")
            await _drain_event_loop()
            assert "result" not in transport.sent(conn)[0]["data"]
            await hub.detach(conn)

    @pytest.mark.asyncio
    async def test_error_omitted_when_none(self) -> None:
        hub, transport = _build_hub()
        with use_test_ws_hub(hub):
            conn = await _attach_subscriber(hub, transport, "t1")
            await notify_step_update(task_id="t1", step_id="s1", status="running")
            await _drain_event_loop()
            assert "error" not in transport.sent(conn)[0]["data"]
            await hub.detach(conn)

    @pytest.mark.asyncio
    async def test_publishes_only_to_matching_task_topic(self) -> None:
        hub, transport = _build_hub()
        with use_test_ws_hub(hub):
            conn1 = await _attach_subscriber(hub, transport, "task-1")
            conn2 = await _attach_subscriber(hub, transport, "task-2")
            await notify_step_update(task_id="task-1", step_id="s1", status="running")
            await _drain_event_loop()
            assert len(transport.sent(conn1)) == 1
            assert len(transport.sent(conn2)) == 0
            await hub.detach(conn1)
            await hub.detach(conn2)

    @pytest.mark.asyncio
    async def test_no_hub_installed_is_silent_noop(self) -> None:
        """Without a hub installed (no app lifespan), notify is best-effort."""
        # _isolate_hub fixture already cleared any installed hub.
        # Should not raise.
        await notify_step_update(task_id="t1", step_id="s1", status="running")
