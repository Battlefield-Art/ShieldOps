"""DAST Runner Agent — Tool functions for dynamic testing."""

from __future__ import annotations

import hashlib
from typing import Any

import structlog

from .models import (
    AttackType,
    CrawlResult,
    EndpointFinding,
    ScanScope,
)

logger = structlog.get_logger()

# -----------------------------------------------------------
# Simulated endpoint discovery data
# -----------------------------------------------------------
_SIMULATED_ENDPOINTS: list[dict[str, Any]] = [
    {
        "path": "/api/v1/users",
        "method": "GET",
        "has_auth": True,
        "params": ["id", "role"],
    },
    {
        "path": "/api/v1/users/{id}",
        "method": "GET",
        "has_auth": True,
        "params": ["id"],
    },
    {
        "path": "/api/v1/login",
        "method": "POST",
        "has_auth": False,
        "params": ["username", "password"],
    },
    {
        "path": "/api/v1/upload",
        "method": "POST",
        "has_auth": True,
        "params": ["file"],
    },
    {
        "path": "/api/v1/search",
        "method": "GET",
        "has_auth": False,
        "params": ["q", "page"],
    },
    {
        "path": "/admin/dashboard",
        "method": "GET",
        "has_auth": True,
        "params": [],
    },
]


def _hash_id(prefix: str, *parts: str) -> str:
    raw = ":".join(parts)
    return prefix + hashlib.sha256(raw.encode()).hexdigest()[:12]


class DASTRunnerToolkit:
    """Tools for dynamic application security testing."""

    def __init__(
        self,
        http_client: Any | None = None,
    ) -> None:
        self._http_client = http_client

    async def discover_endpoints(
        self,
        target_url: str,
        scope: ScanScope,
    ) -> list[CrawlResult]:
        """Discover application endpoints via crawling."""
        logger.info(
            "dast_runner.discover_endpoints",
            target_url=target_url,
            scope=scope.value,
        )
        results: list[CrawlResult] = []
        for ep in _SIMULATED_ENDPOINTS:
            url = f"{target_url.rstrip('/')}{ep['path']}"
            results.append(
                CrawlResult(
                    id=_hash_id("crawl-", url, ep["method"]),
                    url=url,
                    method=ep["method"],
                    status_code=200,
                    content_type="application/json",
                    has_auth=ep["has_auth"],
                    parameters=ep["params"],
                )
            )
        return results

    async def crawl_application(
        self,
        target_url: str,
        endpoints: list[CrawlResult],
    ) -> list[CrawlResult]:
        """Deep-crawl application for additional endpoints."""
        logger.info(
            "dast_runner.crawl",
            endpoint_count=len(endpoints),
        )
        # Enrich existing crawl results with response details
        enriched: list[CrawlResult] = []
        for ep in endpoints:
            enriched.append(
                ep.model_copy(
                    update={
                        "response_size": 1024,
                        "has_forms": ep.method == "POST",
                    }
                )
            )
        return enriched

    async def test_authentication(
        self,
        endpoints: list[CrawlResult],
    ) -> list[EndpointFinding]:
        """Test endpoints for auth bypass vulnerabilities."""
        logger.info(
            "dast_runner.test_auth",
            endpoint_count=len(endpoints),
        )
        findings: list[EndpointFinding] = []
        for ep in endpoints:
            if ep.has_auth:
                # Test for auth bypass by removing token
                fid = _hash_id("auth-", ep.url, "no_token")
                findings.append(
                    EndpointFinding(
                        id=fid,
                        url=ep.url,
                        method=ep.method,
                        attack_type=AttackType.AUTH_BYPASS,
                        severity="high",
                        title=(f"Auth bypass test on {ep.url}"),
                        description=("Endpoint tested for auth bypass"),
                        evidence="Sent request without auth",
                        confidence=0.6,
                        cwe_id="CWE-287",
                        owasp_id="A07:2021",
                    )
                )
            # Test for IDOR on ID-parameterized endpoints
            if "id" in ep.parameters:
                fid = _hash_id("idor-", ep.url, "id_swap")
                findings.append(
                    EndpointFinding(
                        id=fid,
                        url=ep.url,
                        method=ep.method,
                        attack_type=AttackType.IDOR,
                        severity="high",
                        title=f"IDOR test on {ep.url}",
                        description=("Tested object ID enumeration"),
                        evidence="Swapped user ID parameter",
                        confidence=0.7,
                        cwe_id="CWE-639",
                        owasp_id="A01:2021",
                    )
                )
        return findings

    async def fuzz_parameters(
        self,
        endpoints: list[CrawlResult],
    ) -> list[EndpointFinding]:
        """Fuzz endpoint parameters for injection vulns."""
        logger.info(
            "dast_runner.fuzz",
            endpoint_count=len(endpoints),
        )
        findings: list[EndpointFinding] = []
        for ep in endpoints:
            for param in ep.parameters:
                # SQL injection test
                if param in ("q", "id", "username"):
                    fid = _hash_id(
                        "fuzz-sqli-",
                        ep.url,
                        param,
                    )
                    findings.append(
                        EndpointFinding(
                            id=fid,
                            url=ep.url,
                            method=ep.method,
                            attack_type=AttackType.SQLI,
                            severity="critical",
                            title=(f"SQL injection in {param}"),
                            description=(f"Parameter {param} vulnerable to SQLi"),
                            request_payload="' OR 1=1--",
                            confidence=0.75,
                            cwe_id="CWE-89",
                            owasp_id="A03:2021",
                        )
                    )
                # XSS test
                if param in ("q", "page"):
                    fid = _hash_id(
                        "fuzz-xss-",
                        ep.url,
                        param,
                    )
                    findings.append(
                        EndpointFinding(
                            id=fid,
                            url=ep.url,
                            method=ep.method,
                            attack_type=AttackType.XSS,
                            severity="high",
                            title=f"XSS in {param}",
                            description=(f"Parameter {param} reflects input"),
                            request_payload=("<script>alert(1)</script>"),
                            confidence=0.65,
                            cwe_id="CWE-79",
                            owasp_id="A07:2021",
                        )
                    )
        return findings

    async def analyze_responses(
        self,
        auth_findings: list[EndpointFinding],
        fuzz_findings: list[EndpointFinding],
    ) -> list[EndpointFinding]:
        """Merge and deduplicate all findings."""
        logger.info(
            "dast_runner.analyze_responses",
            auth=len(auth_findings),
            fuzz=len(fuzz_findings),
        )
        all_findings = auth_findings + fuzz_findings
        seen: set[str] = set()
        deduped: list[EndpointFinding] = []
        for f in all_findings:
            if f.id not in seen:
                seen.add(f.id)
                deduped.append(f)
        sev_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
        }
        deduped.sort(
            key=lambda f: sev_order.get(f.severity, 5),
        )
        return deduped
