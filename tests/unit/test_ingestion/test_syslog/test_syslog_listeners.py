"""Tests for RFC 5424 syslog TCP/UDP/HTTP ingestion."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.ingestion.syslog.parser import parse_rfc5424
from shieldops.ingestion.syslog.queue import SyslogIngestQueue
from shieldops.ingestion.syslog.tcp_listener import SyslogTCPListener
from shieldops.ingestion.syslog.udp_listener import SyslogUDPListener

SAMPLE_MSG = (
    "<165>1 2026-04-05T10:15:30.123Z host01 sshd 4321 ID47 "
    '[exampleSDID@32473 iut="3" eventSource="Application"] '
    "User login succeeded"
)


def _make_collecting_queue() -> tuple[SyslogIngestQueue, list[dict[str, Any]]]:
    collected: list[dict[str, Any]] = []

    async def handler(event: dict[str, Any], org_id: str) -> str:
        collected.append(event)
        return f"evt-{len(collected)}"

    q = SyslogIngestQueue(org_id="test", max_size=100, handler=handler)
    return q, collected


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parse_rfc5424_valid_message() -> None:
    parsed = parse_rfc5424(SAMPLE_MSG)
    assert parsed["parse_error"] is False
    assert parsed["pri"] == 165
    assert parsed["facility"] == 20
    assert parsed["severity_code"] == 5
    assert parsed["hostname"] == "host01"
    assert parsed["app_name"] == "sshd"
    assert parsed["procid"] == "4321"
    assert parsed["msgid"] == "ID47"
    assert "exampleSDID@32473" in parsed["structured_data"]
    assert parsed["structured_data"]["exampleSDID@32473"]["iut"] == "3"
    assert "User login succeeded" in parsed["msg"]


def test_parse_rfc5424_invalid_message() -> None:
    parsed = parse_rfc5424("not a syslog line at all")
    assert parsed["parse_error"] is True
    assert parsed["message"] == "not a syslog line at all"


# ---------------------------------------------------------------------------
# TCP listener
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tcp_listener_receives_rfc5424() -> None:
    q, collected = _make_collecting_queue()
    listener = SyslogTCPListener(q, host="127.0.0.1", port=0)
    # Bind to an ephemeral port by hand so we can discover it.
    server = await asyncio.start_server(listener._handle_client, host="127.0.0.1", port=0)
    listener._server = server
    port = server.sockets[0].getsockname()[1]
    await q.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write((SAMPLE_MSG + "\n").encode("utf-8"))
        await writer.drain()
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        # Allow drain worker to process
        for _ in range(50):
            if collected:
                break
            await asyncio.sleep(0.02)
        assert len(collected) == 1
        assert collected[0]["hostname"] == "host01"
        assert collected[0]["_transport"] == "tcp"
    finally:
        await q.stop()
        await listener.stop()


@pytest.mark.asyncio
async def test_tcp_listener_octet_counted_framing() -> None:
    q, collected = _make_collecting_queue()
    server = await asyncio.start_server(
        lambda r, w: SyslogTCPListener(q)._handle_client(r, w),
        host="127.0.0.1",
        port=0,
    )
    port = server.sockets[0].getsockname()[1]
    await q.start()
    try:
        msg_bytes = SAMPLE_MSG.encode("utf-8")
        framed = f"{len(msg_bytes)} ".encode() + msg_bytes
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(framed)
        await writer.drain()
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        for _ in range(50):
            if collected:
                break
            await asyncio.sleep(0.02)
        assert len(collected) == 1
        assert collected[0]["app_name"] == "sshd"
    finally:
        server.close()
        await server.wait_closed()
        await q.stop()


# ---------------------------------------------------------------------------
# UDP listener
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_udp_listener_receives_rfc5424() -> None:
    q, collected = _make_collecting_queue()
    listener = SyslogUDPListener(q, host="127.0.0.1", port=0)
    # start() normally binds to configured port; we bind manually for port 0.
    loop = asyncio.get_running_loop()
    from shieldops.ingestion.syslog.udp_listener import _SyslogDatagramProtocol

    transport, _ = await loop.create_datagram_endpoint(
        lambda: _SyslogDatagramProtocol(q), local_addr=("127.0.0.1", 0)
    )
    listener._transport = transport  # type: ignore[assignment]
    port = transport.get_extra_info("sockname")[1]
    await q.start()

    send_transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, remote_addr=("127.0.0.1", port)
    )
    try:
        send_transport.sendto(SAMPLE_MSG.encode("utf-8"))
        for _ in range(50):
            if collected:
                break
            await asyncio.sleep(0.02)
        assert len(collected) == 1
        assert collected[0]["hostname"] == "host01"
        assert collected[0]["_transport"] == "udp"
    finally:
        send_transport.close()
        await q.stop()
        await listener.stop()


# ---------------------------------------------------------------------------
# Backpressure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_queue_drops_oldest_when_full() -> None:
    # Use a queue that never drains so we can deterministically fill it.
    async def never_called(event: dict[str, Any], org_id: str) -> str:
        raise AssertionError("drain worker should not run")

    q = SyslogIngestQueue(org_id="t", max_size=3, handler=never_called)
    # Do NOT start() — we just want to exercise put() backpressure logic.
    assert await q.put("msg1", "tcp") is True
    assert await q.put("msg2", "tcp") is True
    assert await q.put("msg3", "tcp") is True
    # 4th put triggers drop-oldest
    assert await q.put("msg4", "tcp") is False
    assert q.dropped_count == 1
    stats = q.stats()
    assert stats["queue_size"] == 3
    assert stats["dropped"] == 1


# ---------------------------------------------------------------------------
# HTTP fallback endpoint
# ---------------------------------------------------------------------------


def _make_http_app(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    from shieldops.api.routes import webhooks as webhooks_module

    calls: list[tuple[dict[str, Any], str, str]] = []

    async def fake_process_event(
        raw_event: dict[str, Any], source_provider: str, org_id: str
    ) -> str:
        calls.append((raw_event, source_provider, org_id))
        return f"evt-{len(calls)}"

    monkeypatch.setattr(webhooks_module, "process_event", fake_process_event)

    app = FastAPI()
    app.include_router(webhooks_module.router)
    app.state.test_calls = calls  # type: ignore[attr-defined]
    return app


def test_http_syslog_endpoint_text_plain(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _make_http_app(monkeypatch)
    client = TestClient(app)
    response = client.post(
        "/ingest/webhook/syslog",
        headers={"Content-Type": "text/plain", "X-Org-Id": "acme"},
        content=SAMPLE_MSG,
    )
    assert response.status_code == 202
    body = response.json()
    assert body["events_accepted"] == 1
    assert body["events_rejected"] == 0
    calls = app.state.test_calls  # type: ignore[attr-defined]
    assert len(calls) == 1
    event, source, org = calls[0]
    assert source == "syslog"
    assert org == "acme"
    assert event["hostname"] == "host01"
    assert event["_transport"] == "http"


def test_http_syslog_endpoint_json_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _make_http_app(monkeypatch)
    client = TestClient(app)
    response = client.post(
        "/ingest/webhook/syslog",
        json={"messages": [SAMPLE_MSG, SAMPLE_MSG]},
    )
    assert response.status_code == 202
    body = response.json()
    assert body["events_accepted"] == 2


def test_http_syslog_endpoint_empty_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _make_http_app(monkeypatch)
    client = TestClient(app)
    response = client.post(
        "/ingest/webhook/syslog",
        headers={"Content-Type": "text/plain"},
        content="",
    )
    assert response.status_code == 400
