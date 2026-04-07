"""Contract tests for PolicyMiddleware — #243 PR-2.

See ghantakiran/ShieldOps#243. These tests lock the translation layer
that sits between the ASGI pipeline and the pure
:class:`RequestPolicyEngine`:

1. **decision_to_http is total** — every :class:`Decision` subclass
   maps to a well-formed :class:`HttpResponse` (or ``None`` for Allow).
2. **Shadow mode lets every request through** — including rate-limited
   and plan-exceeded ones. Logging + metrics still happen.
3. **Enforce mode short-circuits non-Allow** — sends 429/402 without
   calling ``await self.app(...)``.
4. **Missing-engine fallback** — when the composition root has no
   engine installed, the middleware logs + passes through (same
   compatibility guarantee as #244 PR-2's missing-manager fallback).
5. **Exception safety** — a broken engine or mapper cannot crash the
   request pipeline.

Tests exercise the ASGI surface directly via a recording ``send``
callable — no Starlette TestClient needed.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from shieldops.api.policy.composition import (
    build_in_memory_engine,
    get_policy_engine,
    set_policy_engine,
    use_test_policy_engine,
)
from shieldops.api.policy.middleware import (
    HttpResponse,
    PolicyMiddleware,
    decision_to_http,
    default_request_to_ctx,
)
from shieldops.api.policy.types import (
    Allow,
    Plan,
    PlanExceeded,
    QuotaExceeded,
    RateLimited,
    RequestCtx,
)

# ---------------------------------------------------------------------------
# Pure translator tests — no ASGI context needed.
# ---------------------------------------------------------------------------


class TestDecisionToHttp:
    def test_allow_returns_none(self) -> None:
        assert decision_to_http(Allow()) is None

    def test_rate_limited_maps_to_429(self) -> None:
        resp = decision_to_http(RateLimited(retry_after=2.3, bucket="org-a:default"))
        assert isinstance(resp, HttpResponse)
        assert resp.status_code == 429
        assert resp.body["error"] == "rate_limited"
        assert resp.body["retry_after"] == 2.3
        assert resp.body["bucket"] == "org-a:default"
        # Retry-After header is rounded up so clients don't retry early.
        assert resp.headers["Retry-After"] == "3"
        assert resp.headers["X-ShieldOps-Decision"] == "rate_limited"

    def test_quota_exceeded_maps_to_402(self) -> None:
        resp = decision_to_http(
            QuotaExceeded(quota_name="agents", current=10, limit=10),
        )
        assert resp is not None
        assert resp.status_code == 402
        assert resp.body["error"] == "quota_exceeded"
        assert resp.body["quota_name"] == "agents"
        assert resp.body["current"] == 10
        assert resp.body["limit"] == 10
        assert resp.headers["X-ShieldOps-Decision"] == "quota_exceeded"

    def test_plan_exceeded_maps_to_402(self) -> None:
        resp = decision_to_http(PlanExceeded(reason="denylist", plan="override"))
        assert resp is not None
        assert resp.status_code == 402
        assert resp.body["error"] == "plan_exceeded"
        assert resp.body["reason"] == "denylist"
        assert resp.body["plan"] == "override"
        assert resp.headers["X-ShieldOps-Decision"] == "plan_exceeded"

    def test_unknown_decision_raises_type_error(self) -> None:
        class WeirdDecision:
            pass

        with pytest.raises(TypeError, match="unknown Decision subclass"):
            decision_to_http(WeirdDecision())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Default request_to_ctx mapper
# ---------------------------------------------------------------------------


class _FakeState:
    def __init__(self, **attrs: Any) -> None:
        for k, v in attrs.items():
            setattr(self, k, v)


class _FakeHeaders:
    def __init__(self, headers: dict[str, str]) -> None:
        self._h = {k.lower(): v for k, v in headers.items()}

    def get(self, key: str, default: str = "") -> str:
        return self._h.get(key.lower(), default)


class _FakeRequest:
    def __init__(
        self,
        *,
        org_id: str = "",
        route_class: str = "",
        method: str = "GET",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.state = _FakeState(
            org_id=org_id,
            policy_route_class=route_class,
        )
        self.headers = _FakeHeaders(headers or {})
        self.method = method


class TestDefaultRequestToCtx:
    def test_reads_org_id_from_state(self) -> None:
        ctx = default_request_to_ctx(_FakeRequest(org_id="org-a"))
        assert ctx.org_id == "org-a"
        assert ctx.route_class == "default"
        assert ctx.method == "GET"

    def test_falls_back_to_header(self) -> None:
        ctx = default_request_to_ctx(
            _FakeRequest(headers={"X-Org-Id": "org-b"}),
        )
        assert ctx.org_id == "org-b"

    def test_anonymous_when_nothing_set(self) -> None:
        ctx = default_request_to_ctx(_FakeRequest())
        assert ctx.org_id == "anonymous"

    def test_route_class_override_from_state(self) -> None:
        ctx = default_request_to_ctx(
            _FakeRequest(org_id="org-a", route_class="agents.create"),
        )
        assert ctx.route_class == "agents.create"

    def test_method_is_preserved(self) -> None:
        ctx = default_request_to_ctx(_FakeRequest(org_id="org-a", method="POST"))
        assert ctx.method == "POST"


# ---------------------------------------------------------------------------
# ASGI middleware — exercised through the scope/receive/send callables.
# ---------------------------------------------------------------------------


class _RecordingApp:
    """An ASGI app that records whether it was called and captures scope."""

    def __init__(self) -> None:
        self.called = False
        self.last_scope: dict[str, Any] | None = None

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
    ) -> None:
        self.called = True
        self.last_scope = scope
        # Emit a trivial 200 so the test can verify shadow mode really
        # lets the downstream app respond.
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})


class _SendRecorder:
    """Captures the ASGI messages sent by the middleware / downstream app."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    async def __call__(self, msg: dict[str, Any]) -> None:
        self.messages.append(msg)

    @property
    def status(self) -> int | None:
        for m in self.messages:
            if m.get("type") == "http.response.start":
                return int(m["status"])
        return None

    @property
    def body_json(self) -> dict[str, Any]:
        for m in self.messages:
            if m.get("type") == "http.response.body":
                return json.loads(m["body"].decode("utf-8"))
        return {}


def _make_scope(path: str = "/x", method: str = "GET") -> dict[str, Any]:
    return {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
        "scheme": "http",
        "root_path": "",
    }


async def _noop_receive() -> dict[str, Any]:
    return {"type": "http.request", "body": b"", "more_body": False}


# ---- Factories -----------------------------------------------------------


def _test_ctx_mapper(_request: Any) -> RequestCtx:
    """Bypass the real mapper — pin the ctx to a known org + class."""
    return RequestCtx(org_id="org-a", route_class="default", method="GET")


@pytest.fixture(autouse=True)
def _isolate_policy_engine():
    set_policy_engine(None)
    yield
    set_policy_engine(None)


# ---- Tests ----------------------------------------------------------------


class TestPolicyMiddlewareShadowMode:
    @pytest.mark.asyncio
    async def test_allow_decision_passes_through(self) -> None:
        engine, _deps = build_in_memory_engine(
            default_plan=Plan(tier="starter", rps=1000.0, burst=1000),
        )
        set_policy_engine(engine)

        downstream = _RecordingApp()
        mw = PolicyMiddleware(
            downstream,
            engine_factory=get_policy_engine,
            request_to_ctx=_test_ctx_mapper,
            enforce=False,
        )
        send = _SendRecorder()
        await mw(_make_scope(), _noop_receive, send)

        assert downstream.called
        assert send.status == 200

    @pytest.mark.asyncio
    async def test_rate_limited_decision_is_logged_but_passes_through(self) -> None:
        """Shadow mode: even a RateLimited decision still runs the app."""
        engine, deps = build_in_memory_engine(
            default_plan=Plan(tier="starter", rps=0.0, burst=0),
        )
        set_policy_engine(engine)

        downstream = _RecordingApp()
        mw = PolicyMiddleware(
            downstream,
            engine_factory=get_policy_engine,
            request_to_ctx=_test_ctx_mapper,
            enforce=False,
        )
        send = _SendRecorder()
        await mw(_make_scope(), _noop_receive, send)

        # Downstream WAS called — shadow mode lets everything through.
        assert downstream.called
        assert send.status == 200
        # But an event was emitted to the capturing event log.
        assert any(name == "policy.rate_limited" for name, _ in deps.events.events)


class TestPolicyMiddlewareEnforceMode:
    @pytest.mark.asyncio
    async def test_rate_limited_short_circuits_with_429(self) -> None:
        engine, _deps = build_in_memory_engine(
            default_plan=Plan(tier="starter", rps=0.0, burst=0),
        )
        set_policy_engine(engine)

        downstream = _RecordingApp()
        mw = PolicyMiddleware(
            downstream,
            engine_factory=get_policy_engine,
            request_to_ctx=_test_ctx_mapper,
            enforce=True,
        )
        send = _SendRecorder()
        await mw(_make_scope(), _noop_receive, send)

        assert downstream.called is False
        assert send.status == 429
        assert send.body_json["error"] == "rate_limited"

    @pytest.mark.asyncio
    async def test_quota_exceeded_short_circuits_with_402(self) -> None:
        engine, deps = build_in_memory_engine(
            default_plan=Plan(
                tier="starter",
                rps=1000.0,
                burst=1000,
                quotas={"default": 0},
            ),
        )
        # Usage >= limit = quota exceeded.
        deps.plans.set_usage("org-a", "default", 0)
        set_policy_engine(engine)

        downstream = _RecordingApp()
        mw = PolicyMiddleware(
            downstream,
            engine_factory=get_policy_engine,
            request_to_ctx=_test_ctx_mapper,
            enforce=True,
        )
        send = _SendRecorder()
        await mw(_make_scope(), _noop_receive, send)

        assert downstream.called is False
        assert send.status == 402
        assert send.body_json["error"] == "quota_exceeded"

    @pytest.mark.asyncio
    async def test_allow_passes_through_even_in_enforce_mode(self) -> None:
        engine, _ = build_in_memory_engine(
            default_plan=Plan(tier="starter", rps=1000.0, burst=1000),
        )
        set_policy_engine(engine)

        downstream = _RecordingApp()
        mw = PolicyMiddleware(
            downstream,
            engine_factory=get_policy_engine,
            request_to_ctx=_test_ctx_mapper,
            enforce=True,
        )
        send = _SendRecorder()
        await mw(_make_scope(), _noop_receive, send)

        assert downstream.called
        assert send.status == 200


class TestPolicyMiddlewareFallbacks:
    @pytest.mark.asyncio
    async def test_missing_engine_passes_through(self) -> None:
        """No engine installed → log + pass through (both modes)."""
        downstream = _RecordingApp()
        mw = PolicyMiddleware(
            downstream,
            engine_factory=get_policy_engine,
            request_to_ctx=_test_ctx_mapper,
            enforce=True,
        )
        send = _SendRecorder()
        await mw(_make_scope(), _noop_receive, send)

        assert downstream.called
        assert send.status == 200

    @pytest.mark.asyncio
    async def test_engine_exception_does_not_crash_request(self) -> None:
        """A broken engine is swallowed — request still runs."""

        class _BrokenEngine:
            async def evaluate(self, _ctx: RequestCtx) -> None:
                raise RuntimeError("database down")

        def _broken_factory() -> Any:
            return _BrokenEngine()

        downstream = _RecordingApp()
        mw = PolicyMiddleware(
            downstream,
            engine_factory=_broken_factory,
            request_to_ctx=_test_ctx_mapper,
            enforce=True,
        )
        send = _SendRecorder()
        await mw(_make_scope(), _noop_receive, send)

        assert downstream.called
        assert send.status == 200

    @pytest.mark.asyncio
    async def test_non_http_scope_passes_through_unchanged(self) -> None:
        engine, _ = build_in_memory_engine()
        set_policy_engine(engine)

        downstream = _RecordingApp()
        mw = PolicyMiddleware(
            downstream,
            engine_factory=get_policy_engine,
            request_to_ctx=_test_ctx_mapper,
            enforce=True,
        )
        send = _SendRecorder()
        await mw({"type": "websocket"}, _noop_receive, send)

        assert downstream.called
        assert downstream.last_scope is not None
        assert downstream.last_scope["type"] == "websocket"


class TestPolicyMiddlewareComposition:
    @pytest.mark.asyncio
    async def test_use_test_policy_engine_is_respected_at_call_time(self) -> None:
        """Engine resolution is lazy — swapping via use_test_policy_engine
        between middleware construction + call should take effect."""
        downstream = _RecordingApp()
        mw = PolicyMiddleware(
            downstream,
            engine_factory=get_policy_engine,
            request_to_ctx=_test_ctx_mapper,
            enforce=True,
        )

        # No engine installed at construction time — initially passes through.
        send1 = _SendRecorder()
        await mw(_make_scope(), _noop_receive, send1)
        assert send1.status == 200
        assert downstream.called

        # Now install a deny-everything engine and re-call.
        downstream.called = False
        engine, _ = build_in_memory_engine(
            default_plan=Plan(tier="starter", rps=0.0, burst=0),
        )
        with use_test_policy_engine(engine):
            send2 = _SendRecorder()
            await mw(_make_scope(), _noop_receive, send2)
            assert downstream.called is False
            assert send2.status == 429
