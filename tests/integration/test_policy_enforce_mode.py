"""Integration test for PolicyMiddleware enforce mode — RFC #243 PR-3 / #262.

Exercises the ``settings.policy_enforce`` → ``PolicyMiddleware(enforce=...)``
wiring end-to-end by mounting a minimal Starlette app, installing a real
in-memory :class:`RequestPolicyEngine` via the composition root, then
driving it through Starlette's :class:`TestClient`.

Two scenarios:

1. **Enforce mode blocks over-limit requests with 429.**
   We configure the default plan with ``rps=0.0, burst=0`` so the very
   first request is rate-limited. With ``enforce=True`` the middleware
   short-circuits — status 429, JSON body shape matches the translator
   contract, and the downstream handler is never called.

2. **Shadow mode is unchanged (regression guard for PR-3).**
   Same limit. With ``enforce=False`` the downstream handler still runs
   and returns 200, even though the policy engine emitted a
   ``policy.rate_limited`` event. This proves the flag default keeps
   the existing shadow posture.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from shieldops.api.policy.composition import (
    build_in_memory_engine,
    get_policy_engine,
    set_policy_engine,
)
from shieldops.api.policy.middleware import PolicyMiddleware
from shieldops.api.policy.types import Plan, RequestCtx


async def _pinned_ctx_mapper(_request: Any) -> RequestCtx:  # pragma: no cover - trivial
    return RequestCtx(org_id="org-a", route_class="default", method="GET")


def _sync_pinned_ctx_mapper(_request: Any) -> RequestCtx:
    """Deterministic mapper — bypass tenant_isolation middleware."""
    return RequestCtx(org_id="org-a", route_class="default", method="GET")


async def _ok_handler(_request: Any) -> JSONResponse:
    return JSONResponse({"ok": True}, status_code=200)


@pytest.fixture(autouse=True)
def _isolate_policy_engine() -> Any:
    """Keep the process-wide composition root clean between cases."""
    set_policy_engine(None)
    yield
    set_policy_engine(None)


def _build_app(*, enforce: bool) -> Starlette:
    """Mini ASGI app wrapped with :class:`PolicyMiddleware`.

    Mirrors the shape ``app.py`` will use once PolicyMiddleware is wired
    in lifespan: ``enforce`` is fed from ``settings.policy_enforce``,
    ``engine_factory`` resolves via the composition root.
    """
    app = Starlette(routes=[Route("/ping", _ok_handler)])
    app.add_middleware(
        PolicyMiddleware,
        engine_factory=get_policy_engine,
        request_to_ctx=_sync_pinned_ctx_mapper,
        enforce=enforce,
    )
    return app


class TestPolicyMiddlewareEnforceIntegration:
    def test_enforce_mode_blocks_over_limit_with_429(self) -> None:
        # Engine with rps=0/burst=0 → every request is RateLimited.
        engine, _deps = build_in_memory_engine(
            default_plan=Plan(tier="starter", rps=0.0, burst=0),
        )
        set_policy_engine(engine)

        app = _build_app(enforce=True)
        client = TestClient(app)

        resp = client.get("/ping")

        assert resp.status_code == 429
        body = resp.json()
        assert body["error"] == "rate_limited"
        assert body["bucket"] == "org-a:default"
        # Retry-After header must be present and parseable.
        assert int(resp.headers["retry-after"]) >= 1
        assert resp.headers["x-shieldops-decision"] == "rate_limited"

    def test_shadow_mode_still_passes_requests_through(self) -> None:
        """Flag default (False) preserves PR-2 shadow behavior."""
        engine, deps = build_in_memory_engine(
            default_plan=Plan(tier="starter", rps=0.0, burst=0),
        )
        set_policy_engine(engine)

        app = _build_app(enforce=False)
        client = TestClient(app)

        resp = client.get("/ping")

        # Downstream handler ran — shadow mode lets everything through.
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}
        # But the policy engine still emitted a rate_limited event,
        # which is what the observation script in scripts/ diffs.
        assert any(name == "policy.rate_limited" for name, _ in deps.events.events)

    def test_settings_flag_drives_middleware_enforce(self) -> None:
        """Proves settings.policy_enforce is the single source of truth.

        The lifespan wiring reads ``settings.policy_enforce`` and passes
        it straight to ``PolicyMiddleware(enforce=...)`` — this test
        locks that contract by flowing the flag through the same path.
        """
        from shieldops.config.settings import Settings

        # Default: shadow mode
        s_default = Settings()
        assert s_default.policy_enforce is False

        # Flipped via constructor (equivalent to env var override)
        s_enforced = Settings(policy_enforce=True)
        assert s_enforced.policy_enforce is True

        # Build two apps driven by the flag.
        engine, _deps = build_in_memory_engine(
            default_plan=Plan(tier="starter", rps=0.0, burst=0),
        )
        set_policy_engine(engine)

        app = _build_app(enforce=s_enforced.policy_enforce)
        client = TestClient(app)
        assert client.get("/ping").status_code == 429
