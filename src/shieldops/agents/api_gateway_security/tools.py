"""API Gateway Security Agent — Tool functions for gateway analysis."""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Any

import structlog

from .models import (
    AbuseDetection,
    APIEndpoint,
    APIRisk,
    AuthAnalysis,
    AuthType,
    EndpointScan,
    PolicyEnforcement,
)

logger = structlog.get_logger()

# Thresholds
_HIGH_ERROR_RATE = 0.08
_ABUSE_THRESHOLD = 5000
_DEFAULT_RATE_LIMIT = 200  # requests per minute


class APIGatewaySecurityToolkit:
    """Tools for discovering, analyzing, and securing gateways."""

    # Gateway endpoint catalog (production: query gateway APIs)
    _ENDPOINT_CATALOG: list[tuple[str, str, str, AuthType, bool, bool]] = [
        # (method, path, backend, auth, rate_limited, validated)
        ("GET", "/api/v1/users", "user-svc", AuthType.JWT, True, True),
        ("GET", "/api/v1/users/{id}", "user-svc", AuthType.JWT, True, True),
        ("POST", "/api/v1/users", "user-svc", AuthType.JWT, True, True),
        ("POST", "/api/v1/auth/login", "auth-svc", AuthType.NONE, False, True),
        ("POST", "/api/v1/auth/token", "auth-svc", AuthType.BASIC, False, False),
        ("POST", "/api/v1/auth/refresh", "auth-svc", AuthType.JWT, True, False),
        ("GET", "/api/v1/orders", "order-svc", AuthType.JWT, True, True),
        ("POST", "/api/v1/orders", "order-svc", AuthType.JWT, True, True),
        ("GET", "/api/v1/orders/{id}", "order-svc", AuthType.JWT, False, True),
        ("POST", "/api/v1/payments", "payment-svc", AuthType.OAUTH2, True, True),
        ("GET", "/api/v1/payments/{id}", "payment-svc", AuthType.OAUTH2, True, True),
        ("POST", "/api/v1/webhooks", "webhook-svc", AuthType.API_KEY, False, False),
        ("GET", "/api/v1/admin/config", "admin-svc", AuthType.JWT, False, False),
        ("POST", "/api/v1/admin/users", "admin-svc", AuthType.JWT, False, False),
        ("DELETE", "/api/v1/admin/users/{id}", "admin-svc", AuthType.JWT, False, False),
        ("GET", "/api/v1/search", "search-svc", AuthType.API_KEY, True, False),
        ("POST", "/api/v1/files/upload", "file-svc", AuthType.JWT, True, False),
        ("GET", "/api/v1/files/{id}", "file-svc", AuthType.JWT, True, True),
        ("GET", "/api/v1/reports/export", "report-svc", AuthType.BASIC, False, False),
        ("GET", "/api/v1/internal/metrics", "monitoring", AuthType.NONE, False, False),
        ("GET", "/health", "gateway", AuthType.NONE, False, False),
        ("GET", "/api/v2/users", "user-svc-v2", AuthType.MTLS, True, True),
    ]

    # Auth strength ratings
    _AUTH_STRENGTH: dict[AuthType, tuple[str, APIRisk]] = {
        AuthType.MTLS: ("strong", APIRisk.LOW),
        AuthType.OAUTH2: ("good", APIRisk.LOW),
        AuthType.JWT: ("moderate", APIRisk.MEDIUM),
        AuthType.API_KEY: ("weak", APIRisk.HIGH),
        AuthType.BASIC: ("weak", APIRisk.HIGH),
        AuthType.NONE: ("none", APIRisk.CRITICAL),
    }

    def __init__(
        self,
        gateway_client: Any | None = None,
        waf_client: Any | None = None,
        traffic_store: Any | None = None,
    ) -> None:
        self._gateway_client = gateway_client
        self._waf_client = waf_client
        self._traffic_store = traffic_store

    async def discover_apis(
        self,
        tenant_id: str,
        gateway_ids: list[str] | None = None,
    ) -> list[APIEndpoint]:
        """Discover API endpoints registered on gateways.

        Production: queries gateway admin APIs (Kong, AWS API
        Gateway, Apigee) for registered routes, merges with
        service mesh discovery. Current: simulated catalog.
        """
        logger.info(
            "ags.discover_apis",
            tenant_id=tenant_id,
            gateway_ids=gateway_ids,
        )
        gw_ids = gateway_ids or ["gw-primary"]
        now = time.time()
        tls_versions = ["TLS 1.2", "TLS 1.3", "TLS 1.1"]

        endpoints: list[APIEndpoint] = []
        for gw_id in gw_ids:
            for (
                method,
                path,
                backend,
                auth,
                rl,
                validated,
            ) in self._ENDPOINT_CATALOG:
                eid = hashlib.sha256(
                    f"{gw_id}:{method}:{path}".encode(),
                ).hexdigest()[:12]
                endpoints.append(
                    APIEndpoint(
                        id=eid,
                        method=method,
                        path=path,
                        gateway_id=gw_id,
                        service_backend=backend,
                        auth_type=auth,
                        rate_limit_rpm=(
                            random.randint(50, 500)  # noqa: S311
                            if rl
                            else 0
                        ),
                        rate_limit_enabled=rl,
                        input_validation_enabled=validated,
                        cors_enabled=random.random() > 0.3,  # noqa: S311
                        tls_version=random.choice(tls_versions),  # noqa: S311
                        requests_per_day=random.randint(50, 60_000),  # noqa: S311
                        avg_latency_ms=round(
                            random.uniform(3.0, 800.0),  # noqa: S311
                            1,
                        ),
                        error_rate_pct=round(
                            random.uniform(0.0, 0.12),  # noqa: S311
                            4,
                        ),
                        last_seen=now - random.randint(0, 86_400),  # noqa: S311
                    )
                )

        logger.info("ags.discover_apis.done", count=len(endpoints))
        return endpoints

    async def analyze_auth(
        self,
        endpoints: list[APIEndpoint],
    ) -> list[AuthAnalysis]:
        """Analyze authentication strength and gaps.

        Evaluates auth type, token configuration, scope
        enforcement, and MFA requirements per endpoint.
        """
        logger.info("ags.analyze_auth", count=len(endpoints))
        analyses: list[AuthAnalysis] = []

        for ep in endpoints:
            strength, risk = self._AUTH_STRENGTH.get(
                ep.auth_type,
                ("unknown", APIRisk.HIGH),
            )
            issues: list[str] = []
            recommendation = ""

            if ep.auth_type == AuthType.NONE:
                issues.append("No authentication configured")
                if "internal" not in ep.path and ep.path != "/health":
                    risk = APIRisk.CRITICAL
                    recommendation = "Add JWT or OAuth2 authentication"

            if ep.auth_type == AuthType.BASIC:
                issues.append(
                    "Basic auth transmits credentials per request",
                )
                recommendation = "Upgrade to OAuth2 or JWT"

            if ep.auth_type == AuthType.API_KEY:
                issues.append(
                    "Static API keys lack rotation and scoping",
                )
                recommendation = "Migrate to OAuth2 with scoped tokens"

            if "admin" in ep.path:
                issues.append("Admin endpoint — verify RBAC and MFA")
                if risk != APIRisk.CRITICAL:
                    risk = APIRisk.HIGH

            if ep.auth_type == AuthType.JWT and not ep.rate_limit_enabled:
                issues.append("JWT endpoint without rate limiting")

            scopes = ep.auth_type in (AuthType.OAUTH2, AuthType.MTLS)
            mfa = "admin" in ep.path and ep.auth_type in (
                AuthType.OAUTH2,
                AuthType.MTLS,
            )

            analyses.append(
                AuthAnalysis(
                    id=uuid.uuid4().hex[:12],
                    endpoint_id=ep.id,
                    auth_type=ep.auth_type,
                    auth_strength=strength,
                    risk=risk,
                    issues=issues,
                    token_expiry_minutes=(
                        random.randint(15, 1440)  # noqa: S311
                        if ep.auth_type in (AuthType.JWT, AuthType.OAUTH2)
                        else 0
                    ),
                    scopes_enforced=scopes,
                    mfa_required=mfa,
                    recommendation=recommendation,
                )
            )

        logger.info("ags.analyze_auth.done", count=len(analyses))
        return analyses

    async def scan_endpoints(
        self,
        endpoints: list[APIEndpoint],
    ) -> list[EndpointScan]:
        """Scan endpoints for input validation and config gaps.

        Checks request schema validation, security headers,
        CORS policy, TLS configuration, and response filtering.
        """
        logger.info("ags.scan_endpoints", count=len(endpoints))
        scans: list[EndpointScan] = []

        for ep in endpoints:
            gaps: list[str] = []
            headers: list[str] = []
            violations: list[str] = []
            risk = APIRisk.LOW
            category = "configuration"
            desc_parts: list[str] = []

            # Input validation
            if not ep.input_validation_enabled:
                gaps.append("No request schema validation")
                if ep.method in ("POST", "PUT", "DELETE"):
                    gaps.append(
                        "Write endpoint accepts unvalidated input",
                    )
                    risk = APIRisk.HIGH
                    category = "input_validation"
                    desc_parts.append(
                        "Missing input validation on write endpoint",
                    )

            # Rate limiting
            if not ep.rate_limit_enabled:
                gaps.append("No rate limiting configured")
                if ep.requests_per_day > 10_000:
                    risk = max(
                        risk,
                        APIRisk.HIGH,
                        key=lambda r: list(APIRisk).index(r),
                    )
                    desc_parts.append(
                        "High-traffic endpoint without rate limit",
                    )

            # Security headers (simulate missing)
            required_headers = [
                "Strict-Transport-Security",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Content-Security-Policy",
            ]
            for hdr in required_headers:
                if random.random() < 0.3:  # noqa: S311
                    headers.append(hdr)

            # CORS
            if ep.cors_enabled and random.random() < 0.2:  # noqa: S311
                violations.append(
                    "CORS allows wildcard origin with credentials",
                )
                risk = APIRisk.HIGH
                category = "cors"

            # TLS
            if ep.tls_version == "TLS 1.1":
                violations.append(
                    "Deprecated TLS 1.1 — upgrade to 1.2+",
                )
                risk = max(
                    risk,
                    APIRisk.MEDIUM,
                    key=lambda r: list(APIRisk).index(r),
                )
                category = "tls"

            # Error exposure
            if ep.error_rate_pct > _HIGH_ERROR_RATE:
                violations.append(
                    f"High error rate ({ep.error_rate_pct:.1%}) — "
                    f"verify error responses are sanitized",
                )

            desc = "; ".join(desc_parts) if desc_parts else "OK"
            remediation = ""
            if gaps or violations:
                remediation = "Enable schema validation, add security headers, enforce rate limits"

            scans.append(
                EndpointScan(
                    id=uuid.uuid4().hex[:12],
                    endpoint_id=ep.id,
                    risk=risk,
                    description=desc,
                    category=category,
                    input_validation_gaps=gaps,
                    missing_headers=headers,
                    schema_violations=violations,
                    confidence=round(
                        random.uniform(0.6, 0.95),  # noqa: S311
                        2,
                    ),
                    remediation=remediation,
                )
            )

        logger.info("ags.scan_endpoints.done", count=len(scans))
        return scans

    async def detect_abuse(
        self,
        endpoints: list[APIEndpoint],
    ) -> list[AbuseDetection]:
        """Detect API abuse patterns from traffic analysis.

        Identifies credential stuffing, scraping, rate limit
        bypass, injection probing, and bot activity.
        """
        logger.info("ags.detect_abuse", count=len(endpoints))
        detections: list[AbuseDetection] = []

        for ep in endpoints:
            # Credential stuffing on auth endpoints
            if "auth" in ep.path and ep.requests_per_day > 8_000:
                detections.append(
                    AbuseDetection(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=ep.id,
                        abuse_type="credential_stuffing",
                        source_ip=_random_ip(),
                        request_count=ep.requests_per_day,
                        time_window_minutes=1440,
                        risk=APIRisk.HIGH,
                        description=(
                            f"High-volume auth requests on {ep.path} — credential stuffing"
                        ),
                        blocked=False,
                    )
                )

            # Scraping on list endpoints
            if ep.method == "GET" and "{id}" not in ep.path and ep.requests_per_day > 30_000:
                detections.append(
                    AbuseDetection(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=ep.id,
                        abuse_type="scraping",
                        source_ip=_random_ip(),
                        request_count=ep.requests_per_day,
                        time_window_minutes=1440,
                        risk=APIRisk.MEDIUM,
                        description=f"Systematic scraping on {ep.path}",
                        blocked=False,
                    )
                )

            # Rate limit bypass
            if not ep.rate_limit_enabled and ep.requests_per_day > _ABUSE_THRESHOLD * 5:
                detections.append(
                    AbuseDetection(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=ep.id,
                        abuse_type="rate_limit_bypass",
                        source_ip="0.0.0.0/0",
                        request_count=ep.requests_per_day,
                        time_window_minutes=1440,
                        risk=APIRisk.MEDIUM,
                        description=f"Unrestricted traffic on {ep.path}",
                        blocked=False,
                    )
                )

            # Injection probing
            if ep.method in ("POST", "PUT") and ep.error_rate_pct > _HIGH_ERROR_RATE:
                detections.append(
                    AbuseDetection(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=ep.id,
                        abuse_type="injection_probing",
                        source_ip=_random_ip(),
                        request_count=int(
                            ep.requests_per_day * ep.error_rate_pct,
                        ),
                        time_window_minutes=1440,
                        risk=APIRisk.HIGH,
                        description=(
                            f"Injection probing on {ep.path} — {ep.error_rate_pct:.1%} error rate"
                        ),
                        blocked=False,
                    )
                )

            # Enumeration on parameterized endpoints
            if "{id}" in ep.path and ep.requests_per_day > 40_000:
                detections.append(
                    AbuseDetection(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=ep.id,
                        abuse_type="enumeration",
                        source_ip=_random_ip(),
                        request_count=ep.requests_per_day,
                        time_window_minutes=1440,
                        risk=APIRisk.HIGH,
                        description=f"ID enumeration on {ep.path}",
                        blocked=False,
                    )
                )

        logger.info("ags.detect_abuse.done", count=len(detections))
        return detections

    async def enforce_policies(
        self,
        auth_analyses: list[AuthAnalysis],
        scans: list[EndpointScan],
        abuse_detections: list[AbuseDetection],
    ) -> list[PolicyEnforcement]:
        """Apply enforcement actions to the gateway.

        Production: pushes rules to the gateway admin API, WAF,
        and rate limiter. Current: simulated enforcement.
        """
        logger.info(
            "ags.enforce_policies",
            auth_count=len(auth_analyses),
            scan_count=len(scans),
            abuse_count=len(abuse_detections),
        )
        enforcements: list[PolicyEnforcement] = []
        now = time.time()

        # Auth hardening
        for auth in auth_analyses:
            if auth.risk in (APIRisk.CRITICAL, APIRisk.HIGH):
                enforcements.append(
                    PolicyEnforcement(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=auth.endpoint_id,
                        policy_name="auth_hardening",
                        action=f"upgrade_auth_{auth.auth_type.value}",
                        description=(f"Auth hardening: {'; '.join(auth.issues[:2])}"),
                        enforced_at=now,
                        success=True,
                    )
                )

        # Input validation enforcement
        for scan in scans:
            if scan.input_validation_gaps:
                enforcements.append(
                    PolicyEnforcement(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=scan.endpoint_id,
                        policy_name="input_validation",
                        action="enable_schema_validation",
                        description=(
                            f"Schema validation: {'; '.join(scan.input_validation_gaps[:2])}"
                        ),
                        enforced_at=now,
                        success=True,
                    )
                )

            if "No rate limiting" in str(scan.input_validation_gaps):
                enforcements.append(
                    PolicyEnforcement(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=scan.endpoint_id,
                        policy_name="rate_limit",
                        action=f"apply_rate_limit_{_DEFAULT_RATE_LIMIT}_rpm",
                        description="Applied default rate limit",
                        enforced_at=now,
                        success=True,
                    )
                )

        # Abuse blocking
        for abuse in abuse_detections:
            if abuse.risk in (APIRisk.CRITICAL, APIRisk.HIGH):
                enforcements.append(
                    PolicyEnforcement(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=abuse.endpoint_id,
                        policy_name="ip_block",
                        action=f"block_{abuse.source_ip}",
                        description=(f"Blocked {abuse.abuse_type} from {abuse.source_ip}"),
                        enforced_at=now,
                        success=True,
                    )
                )

        logger.info(
            "ags.enforce_policies.done",
            count=len(enforcements),
        )
        return enforcements


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------


def _random_ip() -> str:
    """Generate a random private IP for simulation."""
    return (
        f"10.{random.randint(0, 255)}"  # noqa: S311
        f".{random.randint(0, 255)}"  # noqa: S311
        f".{random.randint(1, 254)}"  # noqa: S311
    )
