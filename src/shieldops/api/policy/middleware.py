"""PolicyMiddleware — translates :class:`Decision` to HTTP responses.

See ghantakiran/ShieldOps#243 (PR-2). This module is the thin
translation layer that sits between the ASGI pipeline and the pure
:class:`shieldops.api.policy.engine.RequestPolicyEngine`.

Design goals:

1. **The engine stays HTTP-agnostic.** This file is the only place in
   the policy subsystem that knows about HTTP status codes, headers, or
   Starlette's Request/Response types. The engine returns a
   :class:`Decision`; we translate it.

2. **Shadow mode ships by default.** When ``enforce=False`` every
   decision is logged + metered but the request is allowed through.
   This is the PR-2 rollout posture: we land the middleware across all
   routes, observe the decision distribution in dashboards for a full
   week, then flip a single flag to ``enforce=True``. No big-bang
   cutover.

3. **Dependency is explicit.** The middleware takes an engine factory
   (defaulting to :func:`shieldops.api.policy.composition.get_ws_hub`...
   actually :func:`get_policy_engine`) and a ``request_to_ctx`` mapper.
   Tests supply their own mapper; production wires the default mapper
   that reads ``request.state``/headers.

4. **Total translation.** Every :class:`Decision` subclass has an
   explicit branch. Adding a new variant requires editing this file —
   caught at review time, not runtime.

Usage::

    from fastapi import FastAPI
    from shieldops.api.policy.middleware import PolicyMiddleware

    app = FastAPI()
    app.add_middleware(
        PolicyMiddleware,
        engine_factory=get_policy_engine,
        enforce=False,  # shadow mode — log only
    )

The Starlette adapter is :class:`PolicyMiddleware`. The pure
translator is :func:`decision_to_http` — callable without any
ASGI context, making it trivially unit-testable.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import structlog

from shieldops.api.policy.engine import RequestPolicyEngine
from shieldops.api.policy.types import (
    Allow,
    Decision,
    PlanExceeded,
    QuotaExceeded,
    RateLimited,
    RequestCtx,
)

logger = structlog.get_logger(__name__)


__all__ = [
    "HttpResponse",
    "PolicyMiddleware",
    "decision_to_http",
    "default_request_to_ctx",
]


# ---------------------------------------------------------------------------
# Pure translator — HTTP-agnostic until the very last step.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HttpResponse:
    """Framework-agnostic HTTP response shape.

    The Starlette middleware below converts this into a
    :class:`starlette.responses.JSONResponse` at the boundary. Tests can
    assert on this value directly without constructing any Starlette
    types.
    """

    status_code: int
    body: dict[str, Any]
    headers: dict[str, str]


def decision_to_http(decision: Decision) -> HttpResponse | None:
    """Translate a :class:`Decision` into an :class:`HttpResponse`.

    Returns ``None`` for :class:`Allow` (no response to send — the
    request continues down the pipeline). Returns a populated
    :class:`HttpResponse` for every terminal decision.

    The translation is total: every variant of :class:`Decision` has a
    branch here. If a future RFC adds a new variant, the ``raise`` in
    the ``else`` clause will surface it in tests the moment it's
    evaluated.
    """
    if isinstance(decision, Allow):
        return None
    if isinstance(decision, RateLimited):
        retry_after = decision.retry_after
        # Clamp to a sane range: non-negative, finite, and capped at 1h
        # so "refill rate = 0" buckets don't emit ``Retry-After: inf``.
        import math

        if not math.isfinite(retry_after) or retry_after < 0.0:
            retry_after = 3600.0
        retry_after = min(retry_after, 3600.0)
        return HttpResponse(
            status_code=429,
            body={
                "error": "rate_limited",
                "retry_after": retry_after,
                "bucket": decision.bucket,
            },
            headers={
                # Round up so clients never retry too early.
                "Retry-After": str(int(retry_after) + 1),
                "X-ShieldOps-Decision": "rate_limited",
            },
        )
    if isinstance(decision, QuotaExceeded):
        return HttpResponse(
            status_code=402,
            body={
                "error": "quota_exceeded",
                "quota_name": decision.quota_name,
                "current": decision.current,
                "limit": decision.limit,
            },
            headers={"X-ShieldOps-Decision": "quota_exceeded"},
        )
    if isinstance(decision, PlanExceeded):
        return HttpResponse(
            status_code=402,
            body={
                "error": "plan_exceeded",
                "reason": decision.reason,
                "plan": decision.plan,
            },
            headers={"X-ShieldOps-Decision": "plan_exceeded"},
        )
    raise TypeError(
        f"decision_to_http() got an unknown Decision subclass: "
        f"{type(decision).__name__}. Update this translator."
    )


# ---------------------------------------------------------------------------
# Default request → RequestCtx mapper
# ---------------------------------------------------------------------------


def default_request_to_ctx(request: Any) -> RequestCtx:
    """Build a :class:`RequestCtx` from a Starlette ``Request``.

    Reads (in order of preference):
    - ``request.state.org_id`` — set by the tenant_isolation middleware.
    - ``X-Org-Id`` header — fallback for internal health probes.
    - ``"anonymous"`` — if neither is present; the policy engine will
      then consult the default plan.

    ``route_class`` defaults to ``"default"`` but routes can override
    it by setting ``request.state.policy_route_class``.
    """
    state = getattr(request, "state", None)

    org_id = ""
    if state is not None:
        org_id = getattr(state, "org_id", "") or ""
    if not org_id:
        headers = getattr(request, "headers", {}) or {}
        getter = getattr(headers, "get", None)
        org_id = (getter("x-org-id", "") if callable(getter) else "") or "anonymous"

    route_class = "default"
    if state is not None:
        rc = getattr(state, "policy_route_class", "") or ""
        if rc:
            route_class = rc

    method = getattr(request, "method", "GET") or "GET"

    return RequestCtx(org_id=org_id, route_class=route_class, method=method)


# ---------------------------------------------------------------------------
# Starlette middleware — the thin ASGI boundary
# ---------------------------------------------------------------------------


RequestToCtx = Callable[[Any], RequestCtx]
EngineFactory = Callable[[], RequestPolicyEngine]


class PolicyMiddleware:
    """ASGI middleware that runs the policy engine on every request.

    Works with Starlette/FastAPI via ``app.add_middleware(...)``. In
    shadow mode (``enforce=False``) it logs the decision + lets the
    request through; in enforce mode it short-circuits with the
    translated :class:`HttpResponse` for non-Allow decisions.

    The middleware resolves the engine lazily via ``engine_factory()``
    on every request. This is intentional so tests can swap the
    installed engine at runtime and the middleware picks it up on the
    next call — no re-instantiation of the app.
    """

    def __init__(
        self,
        app: Any,
        *,
        engine_factory: EngineFactory,
        request_to_ctx: RequestToCtx = default_request_to_ctx,
        enforce: bool = False,
    ) -> None:
        self.app = app
        self._engine_factory = engine_factory
        self._request_to_ctx = request_to_ctx
        self.enforce = enforce

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        # Only intercept HTTP — pass websocket + lifespan straight through.
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        from starlette.requests import Request  # local import — soft dep

        request = Request(scope, receive=receive)
        try:
            engine = self._engine_factory()
        except RuntimeError:
            # No engine installed — log once + let the request through.
            # Same compatibility guarantee as the #244 PR-2 missing-manager
            # fallback: until `set_policy_engine(...)` is called at
            # lifespan, the middleware is a no-op.
            logger.debug("policy.middleware.engine_not_installed")
            await self.app(scope, receive, send)
            return

        try:
            ctx = self._request_to_ctx(request)
            decision = await engine.evaluate(ctx)
        except Exception as exc:  # noqa: BLE001
            # Broken engine or mapper must never crash the request.
            logger.warning(
                "policy.middleware.evaluate_failed",
                error=str(exc),
                path=scope.get("path", ""),
            )
            await self.app(scope, receive, send)
            return

        response = decision_to_http(decision)
        logger.info(
            "policy.middleware.decision",
            decision=type(decision).__name__,
            enforce=self.enforce,
            path=scope.get("path", ""),
            org_id=ctx.org_id,
            route_class=ctx.route_class,
        )

        if response is None or not self.enforce:
            # Allow path, or shadow mode: log only + continue.
            await self.app(scope, receive, send)
            return

        # Enforce mode with a non-Allow decision: short-circuit.
        await _send_json_response(send, response)


async def _send_json_response(
    send: Callable[[dict[str, Any]], Awaitable[None]],
    response: HttpResponse,
) -> None:
    """Emit the :class:`HttpResponse` directly via the ASGI ``send`` callable.

    Avoiding :class:`starlette.responses.JSONResponse` here keeps the
    middleware testable without a full Starlette test client — any
    recording ``send`` callable captures the exact bytes.
    """
    import json

    body = json.dumps(response.body).encode("utf-8")
    headers_list: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    for k, v in response.headers.items():
        headers_list.append((k.lower().encode("ascii"), v.encode("ascii")))
    await send(
        {
            "type": "http.response.start",
            "status": response.status_code,
            "headers": headers_list,
        }
    )
    await send({"type": "http.response.body", "body": body})
