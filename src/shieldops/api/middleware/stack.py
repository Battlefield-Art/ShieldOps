"""Declarative middleware stack for the ShieldOps API.

Translates the implicit ``add_middleware`` calls in ``app.py`` into a
validated, topologically-sorted stack using :class:`MiddlewareStackBuilder`.

Usage::

    from shieldops.api.middleware.stack import build_middleware_stack
    names = build_middleware_stack(app, settings)
"""

from __future__ import annotations

from typing import Any

import structlog
from starlette.middleware.cors import CORSMiddleware

from shieldops.api.middleware import (
    APIVersionMiddleware,
    ErrorHandlerMiddleware,
    GracefulShutdownMiddleware,
    MetricsMiddleware,
    RequestIDMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
    TenantMiddleware,
    UsageTrackerMiddleware,
)
from shieldops.api.middleware.builder import (
    MiddlewareSpec,
    MiddlewareStackBuilder,
    Position,
)
from shieldops.api.policy.composition import get_policy_engine
from shieldops.api.policy.middleware import PolicyMiddleware

logger = structlog.get_logger()


def build_middleware_stack(app: Any, settings: Any) -> list[str]:
    """Build and apply the full ShieldOps middleware stack.

    Parameters
    ----------
    app:
        A FastAPI / Starlette application instance.
    settings:
        Application settings object (must expose ``cors_origins``,
        ``sliding_window_rate_limit_enabled``, ``idempotency_ttl_seconds``).

    Returns
    -------
    list[str]
        Middleware names in outermost-first execution order.
    """
    builder = MiddlewareStackBuilder()

    # -- OUTERMOST: graceful shutdown rejects early during drain --------
    builder.add(
        MiddlewareSpec(
            cls=GracefulShutdownMiddleware,
            name="graceful_shutdown",
            position=Position.OUTERMOST,
            tags=frozenset({"lifecycle"}),
        )
    )

    # -- Metrics: wraps everything except shutdown ----------------------
    builder.add(
        MiddlewareSpec(
            cls=MetricsMiddleware,
            name="metrics",
            must_run_after=frozenset({"graceful_shutdown"}),
            must_run_before=frozenset({"security_headers"}),
            tags=frozenset({"observability"}),
        )
    )

    # -- Security headers: HSTS, CSP, X-Frame-Options ------------------
    builder.add(
        MiddlewareSpec(
            cls=SecurityHeadersMiddleware,
            name="security_headers",
            must_run_before=frozenset({"api_version"}),
            tags=frozenset({"security"}),
        )
    )

    # -- API versioning: X-API-Version + X-Powered-By ------------------
    builder.add(
        MiddlewareSpec(
            cls=APIVersionMiddleware,
            name="api_version",
            must_run_before=frozenset({"request_id"}),
        )
    )

    # -- Request ID: assigns correlation ID ----------------------------
    builder.add(
        MiddlewareSpec(
            cls=RequestIDMiddleware,
            name="request_id",
            must_run_before=frozenset({"request_logging"}),
            tags=frozenset({"observability"}),
        )
    )

    # -- Request logging: structured access logs -----------------------
    builder.add(
        MiddlewareSpec(
            cls=RequestLoggingMiddleware,
            name="request_logging",
            must_run_before=frozenset({"usage_tracker"}),
            tags=frozenset({"observability"}),
        )
    )

    # -- Usage tracker: per-endpoint call counts -----------------------
    builder.add(
        MiddlewareSpec(
            cls=UsageTrackerMiddleware,
            name="usage_tracker",
            must_run_before=frozenset({"policy"}),
            tags=frozenset({"billing"}),
        )
    )

    # -- Policy enforcement: unified rate-limit + quota + overrides ----
    # RFC #243 PR-4 / #263 replaced BillingEnforcementMiddleware +
    # RateLimitMiddleware + SlidingWindowRateLimiter with a single
    # PolicyMiddleware backed by RequestPolicyEngine. The engine is
    # resolved lazily via get_policy_engine() so tests can swap it via
    # use_test_policy_engine().
    builder.add(
        MiddlewareSpec(
            cls=PolicyMiddleware,
            name="policy",
            kwargs={
                "engine_factory": get_policy_engine,
                "enforce": getattr(settings, "policy_enforce", True),
            },
            tags=frozenset({"rate_limiting", "billing"}),
        )
    )

    # -- Idempotency: POST/PUT/PATCH deduplication (optional) ----------
    try:
        from shieldops.api.middleware.idempotency import IdempotencyMiddleware

        builder.add(
            MiddlewareSpec(
                cls=IdempotencyMiddleware,
                name="idempotency",
                kwargs={"ttl": getattr(settings, "idempotency_ttl_seconds", 300)},
                optional=True,
                must_run_after=frozenset({"policy"}),
            )
        )
    except ImportError:
        logger.debug("idempotency_middleware_not_available")

    # -- INNERMOST: error handler catches everything -------------------
    builder.add(
        MiddlewareSpec(
            cls=ErrorHandlerMiddleware,
            name="error_handler",
            position=Position.INNERMOST,
        )
    )

    # -- Tenant isolation (optional) -----------------------------------
    builder.add(
        MiddlewareSpec(
            cls=TenantMiddleware,
            name="tenant",
            optional=True,
            must_run_after=frozenset({"request_id"}),
            must_run_before=frozenset({"error_handler"}),
            tags=frozenset({"security"}),
        )
    )

    # -- CORS (no ordering constraints — Starlette handles it) ---------
    builder.add(
        MiddlewareSpec(
            cls=CORSMiddleware,
            name="cors",
            kwargs={
                "allow_origins": getattr(settings, "cors_origins", ["*"]),
                "allow_credentials": True,
                "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": [
                    "Authorization",
                    "Content-Type",
                    "X-Request-ID",
                    "X-Organization-ID",
                    "Idempotency-Key",
                ],
            },
            must_run_after=frozenset({"graceful_shutdown"}),
            must_run_before=frozenset({"error_handler"}),
        )
    )

    # -- Validate and build --------------------------------------------
    warnings = builder.validate()
    for w in warnings:
        logger.warning("middleware_stack_warning", detail=w)

    return builder.build(app)
