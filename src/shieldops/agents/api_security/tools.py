"""API Security Agent — Tool functions for API endpoint security analysis."""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Any

import structlog

from .models import (
    AbuseType,
    APIAbuseIncident,
    APIEndpoint,
    APISeverity,
    APIVulnerability,
    PolicyEnforcement,
    VulnerabilityType,
)

logger = structlog.get_logger()

# Default thresholds
_HIGH_ERROR_RATE = 0.10
_HIGH_LATENCY_MS = 2000.0
_ABUSE_REQUEST_THRESHOLD = 1000
_RATE_LIMIT_DEFAULT = 100  # requests per minute


class APISecurityToolkit:
    """Tools for discovering, scanning, and securing API endpoints."""

    # OWASP API Security Top 10 patterns
    OWASP_API_TOP_10: dict[str, dict[str, Any]] = {
        "API1:2023": {
            "name": "Broken Object Level Authorization",
            "vuln_type": VulnerabilityType.BOLA,
            "indicators": [
                "sequential_ids",
                "no_ownership_check",
                "direct_object_reference",
            ],
            "cwe": "CWE-285",
            "severity": APISeverity.CRITICAL,
        },
        "API2:2023": {
            "name": "Broken Authentication",
            "vuln_type": VulnerabilityType.BROKEN_AUTH,
            "indicators": [
                "weak_token",
                "no_rate_limit_auth",
                "credential_in_url",
            ],
            "cwe": "CWE-287",
            "severity": APISeverity.CRITICAL,
        },
        "API3:2023": {
            "name": "Broken Object Property Level Authorization",
            "vuln_type": VulnerabilityType.EXCESSIVE_DATA,
            "indicators": [
                "excessive_fields",
                "no_field_filtering",
                "sensitive_in_response",
            ],
            "cwe": "CWE-213",
            "severity": APISeverity.HIGH,
        },
        "API4:2023": {
            "name": "Unrestricted Resource Consumption",
            "vuln_type": VulnerabilityType.RESOURCE_LACK,
            "indicators": [
                "no_rate_limit",
                "no_pagination_limit",
                "unbounded_query",
            ],
            "cwe": "CWE-770",
            "severity": APISeverity.HIGH,
        },
        "API5:2023": {
            "name": "Broken Function Level Authorization",
            "vuln_type": VulnerabilityType.FUNCTION_LEVEL_AUTH,
            "indicators": [
                "admin_accessible",
                "privilege_escalation",
                "missing_rbac",
            ],
            "cwe": "CWE-285",
            "severity": APISeverity.CRITICAL,
        },
        "API6:2023": {
            "name": "Unrestricted Access to Sensitive Business Flows",
            "vuln_type": VulnerabilityType.MASS_ASSIGNMENT,
            "indicators": [
                "mass_assignment",
                "unexpected_fields_accepted",
                "no_schema_validation",
            ],
            "cwe": "CWE-915",
            "severity": APISeverity.HIGH,
        },
        "API7:2023": {
            "name": "Server Side Request Forgery",
            "vuln_type": VulnerabilityType.SSRF,
            "indicators": [
                "url_parameter",
                "redirect_param",
                "webhook_url_input",
            ],
            "cwe": "CWE-918",
            "severity": APISeverity.HIGH,
        },
        "API8:2023": {
            "name": "Security Misconfiguration",
            "vuln_type": VulnerabilityType.SECURITY_MISCONFIG,
            "indicators": [
                "verbose_errors",
                "debug_enabled",
                "missing_cors",
                "default_credentials",
            ],
            "cwe": "CWE-16",
            "severity": APISeverity.MEDIUM,
        },
        "API9:2023": {
            "name": "Improper Inventory Management",
            "vuln_type": VulnerabilityType.IMPROPER_ASSET,
            "indicators": [
                "undocumented_endpoint",
                "deprecated_active",
                "shadow_api",
            ],
            "cwe": "CWE-1059",
            "severity": APISeverity.MEDIUM,
        },
        "API10:2023": {
            "name": "Unsafe Consumption of APIs",
            "vuln_type": VulnerabilityType.INJECTION,
            "indicators": [
                "sql_injection",
                "nosql_injection",
                "command_injection",
                "xss_payload",
            ],
            "cwe": "CWE-89",
            "severity": APISeverity.CRITICAL,
        },
    }

    def __init__(
        self,
        api_gateway: Any | None = None,
        waf_client: Any | None = None,
        traffic_store: Any | None = None,
    ) -> None:
        self._api_gateway = api_gateway
        self._waf_client = waf_client
        self._traffic_store = traffic_store

    async def discover_endpoints(
        self,
        tenant_id: str,
        scope: list[str] | None = None,
    ) -> list[APIEndpoint]:
        """Discover API endpoints from gateway, service mesh, or OpenAPI specs.

        In production this queries the API gateway / mesh for registered
        routes and merges with OpenAPI spec discovery.  The current
        implementation generates realistic simulated data.
        """
        logger.info(
            "api_security.discover_endpoints",
            tenant_id=tenant_id,
            scope=scope,
        )
        scope = scope or ["default"]
        now = time.time()

        # Simulated endpoint catalog (production: query gateway/mesh)
        endpoint_templates = [
            ("GET", "/api/v1/users", "user-service", True),
            ("GET", "/api/v1/users/{id}", "user-service", True),
            ("POST", "/api/v1/users", "user-service", True),
            ("PUT", "/api/v1/users/{id}", "user-service", True),
            ("DELETE", "/api/v1/users/{id}", "user-service", True),
            ("POST", "/api/v1/auth/login", "auth-service", False),
            ("POST", "/api/v1/auth/token/refresh", "auth-service", True),
            ("GET", "/api/v1/orders", "order-service", True),
            ("GET", "/api/v1/orders/{id}", "order-service", True),
            ("POST", "/api/v1/orders", "order-service", True),
            ("GET", "/api/v1/payments", "payment-service", True),
            ("POST", "/api/v1/payments", "payment-service", True),
            ("GET", "/api/v1/admin/config", "admin-service", True),
            ("POST", "/api/v1/admin/users", "admin-service", True),
            ("GET", "/api/v1/search", "search-service", False),
            ("POST", "/api/v1/webhooks", "webhook-service", True),
            ("GET", "/api/v1/files/{id}", "file-service", True),
            ("POST", "/api/v1/files/upload", "file-service", True),
            ("GET", "/health", "gateway", False),
            ("GET", "/api/v1/internal/metrics", "monitoring", False),
        ]

        endpoints: list[APIEndpoint] = []
        for method, path, service, auth in endpoint_templates:
            if scope != ["default"] and service not in scope:
                continue
            eid = hashlib.sha256(f"{method}:{path}:{service}".encode()).hexdigest()[:12]
            endpoints.append(
                APIEndpoint(
                    id=eid,
                    method=method,
                    path=path,
                    service=service,
                    auth_required=auth,
                    rate_limited=random.random() > 0.4,  # noqa: S311
                    requests_per_day=random.randint(100, 50_000),  # noqa: S311
                    avg_latency_ms=round(random.uniform(5.0, 500.0), 1),  # noqa: S311
                    error_rate=round(random.uniform(0.0, 0.15), 4),  # noqa: S311
                    last_scanned=now - random.randint(0, 86_400),  # noqa: S311
                )
            )

        logger.info(
            "api_security.discover_endpoints.done",
            count=len(endpoints),
        )
        return endpoints

    async def analyze_traffic(
        self,
        endpoints: list[APIEndpoint],
    ) -> list[APIEndpoint]:
        """Enrich endpoints with live traffic analytics.

        Production: pull metrics from the traffic store / gateway logs.
        """
        logger.info("api_security.analyze_traffic", count=len(endpoints))

        enriched: list[APIEndpoint] = []
        for ep in endpoints:
            # Simulate traffic enrichment (production: real metrics)
            enriched.append(
                ep.model_copy(
                    update={
                        "requests_per_day": ep.requests_per_day + random.randint(-200, 500),  # noqa: S311
                        "avg_latency_ms": round(
                            ep.avg_latency_ms + random.uniform(-10.0, 50.0),  # noqa: S311
                            1,
                        ),
                        "error_rate": round(
                            max(0.0, ep.error_rate + random.uniform(-0.02, 0.05)),  # noqa: S311
                            4,
                        ),
                        "last_scanned": time.time(),
                    }
                )
            )

        return enriched

    async def detect_vulnerabilities(
        self,
        endpoints: list[APIEndpoint],
    ) -> list[APIVulnerability]:
        """Scan endpoints for OWASP API Security Top 10 vulnerabilities.

        Applies heuristic checks against each endpoint, mapping findings
        to specific OWASP categories with CWE references.
        """
        logger.info("api_security.detect_vulnerabilities", count=len(endpoints))
        vulns: list[APIVulnerability] = []

        for ep in endpoints:
            # API1 — BOLA: endpoints with path params and sequential IDs
            if "{id}" in ep.path:
                vulns.append(
                    self._make_vuln(
                        ep,
                        "API1:2023",
                        f"Endpoint {ep.method} {ep.path} uses path-based object "
                        f"references — verify ownership checks are enforced",
                        confidence=0.7,
                    )
                )

            # API2 — Broken Auth: auth endpoints without rate limiting
            if "auth" in ep.path and not ep.rate_limited:
                vulns.append(
                    self._make_vuln(
                        ep,
                        "API2:2023",
                        f"Auth endpoint {ep.path} lacks rate limiting — "
                        f"vulnerable to credential stuffing",
                        confidence=0.85,
                    )
                )

            # API3 — Excessive Data: GET endpoints returning high volumes
            if ep.method == "GET" and ep.avg_latency_ms > _HIGH_LATENCY_MS:
                vulns.append(
                    self._make_vuln(
                        ep,
                        "API3:2023",
                        f"Endpoint {ep.path} has high latency "
                        f"({ep.avg_latency_ms}ms) — may return excessive data",
                        confidence=0.5,
                    )
                )

            # API4 — Resource consumption: no rate limiting
            if not ep.rate_limited and ep.requests_per_day > 10_000:
                vulns.append(
                    self._make_vuln(
                        ep,
                        "API4:2023",
                        f"High-traffic endpoint {ep.path} "
                        f"({ep.requests_per_day} req/day) has no rate limiting",
                        confidence=0.8,
                    )
                )

            # API5 — Function level auth: admin endpoints
            if "admin" in ep.path:
                vulns.append(
                    self._make_vuln(
                        ep,
                        "API5:2023",
                        f"Admin endpoint {ep.path} — verify RBAC enforcement "
                        f"and privilege separation",
                        confidence=0.65,
                    )
                )

            # API7 — SSRF: webhook/URL input endpoints
            if "webhook" in ep.path or "upload" in ep.path:
                vulns.append(
                    self._make_vuln(
                        ep,
                        "API7:2023",
                        f"Endpoint {ep.path} accepts external URLs/files — verify SSRF protections",
                        confidence=0.6,
                    )
                )

            # API8 — Misconfig: unprotected internal endpoints
            if not ep.auth_required and "internal" in ep.path:
                vulns.append(
                    self._make_vuln(
                        ep,
                        "API8:2023",
                        f"Internal endpoint {ep.path} is publicly accessible "
                        f"without authentication",
                        confidence=0.9,
                    )
                )

            # API9 — Improper assets: health/internal exposed
            if ep.path in ("/health", "/api/v1/internal/metrics"):
                vulns.append(
                    self._make_vuln(
                        ep,
                        "API9:2023",
                        f"Infrastructure endpoint {ep.path} is exposed — should be internal-only",
                        confidence=0.75,
                    )
                )

            # API10 — Injection: POST/PUT endpoints with high error rates
            if ep.method in ("POST", "PUT") and ep.error_rate > _HIGH_ERROR_RATE:
                vulns.append(
                    self._make_vuln(
                        ep,
                        "API10:2023",
                        f"Write endpoint {ep.path} has elevated error rate "
                        f"({ep.error_rate:.2%}) — may indicate injection attempts",
                        confidence=0.55,
                    )
                )

        logger.info("api_security.detect_vulnerabilities.done", count=len(vulns))
        return vulns

    async def detect_abuse(
        self,
        endpoints: list[APIEndpoint],
    ) -> list[APIAbuseIncident]:
        """Detect API abuse patterns from endpoint traffic analysis."""
        logger.info("api_security.detect_abuse", count=len(endpoints))
        incidents: list[APIAbuseIncident] = []

        for ep in endpoints:
            # Credential stuffing on auth endpoints
            if "auth" in ep.path and ep.requests_per_day > 5_000:
                incidents.append(
                    APIAbuseIncident(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=ep.id,
                        abuse_type=AbuseType.CREDENTIAL_STUFFING,
                        source_ip=f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24",  # noqa: S311
                        request_count=ep.requests_per_day,
                        time_window_minutes=1440,
                        description=(
                            f"High-volume auth requests on {ep.path} — "
                            f"potential credential stuffing"
                        ),
                        severity=APISeverity.HIGH,
                        blocked=False,
                    )
                )

            # Scraping on list endpoints
            if (
                ep.method == "GET"
                and "{id}" not in ep.path
                and ep.requests_per_day > _ABUSE_REQUEST_THRESHOLD * 20
            ):
                incidents.append(
                    APIAbuseIncident(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=ep.id,
                        abuse_type=AbuseType.SCRAPING,
                        source_ip=(
                            f"192.168.{random.randint(0, 255)}"  # noqa: S311
                            f".{random.randint(1, 254)}"  # noqa: S311
                        ),
                        request_count=ep.requests_per_day,
                        time_window_minutes=1440,
                        description=(f"Systematic scraping detected on {ep.path}"),
                        severity=APISeverity.MEDIUM,
                        blocked=False,
                    )
                )

            # Enumeration on parameterized endpoints
            if "{id}" in ep.path and ep.requests_per_day > 30_000:
                incidents.append(
                    APIAbuseIncident(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=ep.id,
                        abuse_type=AbuseType.ENUMERATION,
                        source_ip=(
                            f"172.16.{random.randint(0, 255)}"  # noqa: S311
                            f".{random.randint(1, 254)}"  # noqa: S311
                        ),
                        request_count=ep.requests_per_day,
                        time_window_minutes=1440,
                        description=(f"ID enumeration detected on {ep.path}"),
                        severity=APISeverity.HIGH,
                        blocked=False,
                    )
                )

            # Rate abuse — high traffic without rate limiting
            if not ep.rate_limited and ep.requests_per_day > _ABUSE_REQUEST_THRESHOLD * 30:
                incidents.append(
                    APIAbuseIncident(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=ep.id,
                        abuse_type=AbuseType.RATE_ABUSE,
                        source_ip="0.0.0.0/0",
                        request_count=ep.requests_per_day,
                        time_window_minutes=1440,
                        description=(
                            f"Unrestricted traffic on {ep.path} — no rate limiting enforced"
                        ),
                        severity=APISeverity.MEDIUM,
                        blocked=False,
                    )
                )

        logger.info("api_security.detect_abuse.done", count=len(incidents))
        return incidents

    async def enforce_policies(
        self,
        vulnerabilities: list[APIVulnerability],
        abuse_incidents: list[APIAbuseIncident],
    ) -> list[PolicyEnforcement]:
        """Apply security enforcement actions based on findings.

        Production: pushes WAF rules, rate-limit configs, and auth
        requirements to the API gateway.
        """
        logger.info(
            "api_security.enforce_policies",
            vuln_count=len(vulnerabilities),
            abuse_count=len(abuse_incidents),
        )
        enforcements: list[PolicyEnforcement] = []
        now = time.time()

        # Enforce rate limiting for unprotected high-risk endpoints
        for vuln in vulnerabilities:
            if vuln.vulnerability_type in (
                VulnerabilityType.RESOURCE_LACK,
                VulnerabilityType.BROKEN_AUTH,
            ):
                enforcements.append(
                    PolicyEnforcement(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=vuln.endpoint_id,
                        policy_name="rate_limit",
                        action=f"apply_rate_limit_{_RATE_LIMIT_DEFAULT}_rpm",
                        description=(
                            f"Applied rate limit for {vuln.owasp_reference}: "
                            f"{vuln.description[:80]}"
                        ),
                        enforced_at=now,
                        success=True,
                    )
                )

            # WAF rule for injection / SSRF
            if vuln.vulnerability_type in (
                VulnerabilityType.INJECTION,
                VulnerabilityType.SSRF,
            ):
                enforcements.append(
                    PolicyEnforcement(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=vuln.endpoint_id,
                        policy_name="waf_rule",
                        action="deploy_waf_pattern_block",
                        description=(
                            f"WAF rule for {vuln.owasp_reference}: {vuln.description[:80]}"
                        ),
                        enforced_at=now,
                        success=True,
                    )
                )

            # Auth hardening for privilege issues
            if vuln.vulnerability_type in (
                VulnerabilityType.BOLA,
                VulnerabilityType.FUNCTION_LEVEL_AUTH,
            ):
                enforcements.append(
                    PolicyEnforcement(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=vuln.endpoint_id,
                        policy_name="auth_hardening",
                        action="enforce_ownership_check",
                        description=(
                            f"Auth hardening for {vuln.owasp_reference}: {vuln.description[:80]}"
                        ),
                        enforced_at=now,
                        success=True,
                    )
                )

        # Block abuse source IPs
        for incident in abuse_incidents:
            if incident.severity in (APISeverity.CRITICAL, APISeverity.HIGH):
                enforcements.append(
                    PolicyEnforcement(
                        id=uuid.uuid4().hex[:12],
                        endpoint_id=incident.endpoint_id,
                        policy_name="ip_block",
                        action=f"block_source_{incident.source_ip}",
                        description=(
                            f"Blocked {incident.abuse_type.value} from "
                            f"{incident.source_ip} on endpoint "
                            f"{incident.endpoint_id}"
                        ),
                        enforced_at=now,
                        success=True,
                    )
                )

        logger.info(
            "api_security.enforce_policies.done",
            count=len(enforcements),
        )
        return enforcements

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_vuln(
        self,
        endpoint: APIEndpoint,
        owasp_ref: str,
        description: str,
        confidence: float,
    ) -> APIVulnerability:
        """Create a vulnerability finding from an OWASP pattern match."""
        pattern = self.OWASP_API_TOP_10.get(owasp_ref, {})
        return APIVulnerability(
            id=uuid.uuid4().hex[:12],
            endpoint_id=endpoint.id,
            vulnerability_type=pattern.get("vuln_type", VulnerabilityType.SECURITY_MISCONFIG),
            description=description,
            severity=pattern.get("severity", APISeverity.MEDIUM),
            confidence=confidence,
            owasp_reference=owasp_ref,
            remediation=f"See OWASP {owasp_ref}: {pattern.get('name', '')}",
            cwe_id=pattern.get("cwe", ""),
        )
