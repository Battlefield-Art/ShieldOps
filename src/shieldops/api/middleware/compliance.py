"""Compliance enforcement middleware.

Intercepts API requests to enforce PII redaction, audit logging,
and framework-specific controls before processing.
"""

from __future__ import annotations

import re
import time
from collections.abc import Sequence
from typing import Any

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = structlog.get_logger(__name__)

# Paths exempt from compliance checks (health/readiness probes, metrics)
EXEMPT_PATHS: frozenset[str] = frozenset({"/health", "/ready", "/metrics"})

# Common PII patterns for scanning
PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone_us": re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
}

# Compliance headers added to every non-exempt response
COMPLIANCE_HEADERS: dict[str, str] = {
    "X-Compliance-Enforced": "true",
    "X-Data-Classification": "internal",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}

# Sensitive path prefixes that require stricter controls
SENSITIVE_PATH_PREFIXES: tuple[str, ...] = (
    "/api/v1/agents/",
    "/api/v1/remediation/",
    "/api/v1/security/",
    "/api/v1/billing/",
    "/api/v1/compliance/",
)


class PIIDetector:
    """Scan text for common PII patterns."""

    def __init__(self, extra_patterns: dict[str, re.Pattern[str]] | None = None) -> None:
        self._patterns = dict(PII_PATTERNS)
        if extra_patterns:
            self._patterns.update(extra_patterns)

    def scan(self, text: str) -> list[dict[str, str]]:
        """Return list of PII findings with type and redacted match."""
        findings: list[dict[str, str]] = []
        for pii_type, pattern in self._patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                findings.append(
                    {
                        "type": pii_type,
                        "match_redacted": self._redact(match),
                    }
                )
        return findings

    @staticmethod
    def _redact(value: str) -> str:
        """Redact all but last 4 characters."""
        if len(value) <= 4:
            return "****"
        return "*" * (len(value) - 4) + value[-4:]

    def has_pii(self, text: str) -> bool:
        """Return True if any PII pattern matches."""
        return any(pattern.search(text) for pattern in self._patterns.values())


class SecurityAuditLogger:
    """Structured audit logger for compliance events."""

    def __init__(self) -> None:
        self._logger = structlog.get_logger("compliance.audit")

    async def log_request(
        self,
        *,
        request_id: str,
        method: str,
        path: str,
        user_id: str | None,
        tenant_id: str | None,
        frameworks: Sequence[str],
        pii_detected: bool,
        status_code: int,
        duration_ms: float,
    ) -> None:
        """Log a compliance audit event."""
        self._logger.info(
            "compliance_audit",
            request_id=request_id,
            method=method,
            path=path,
            user_id=user_id,
            tenant_id=tenant_id,
            frameworks=list(frameworks),
            pii_detected=pii_detected,
            status_code=status_code,
            duration_ms=round(duration_ms, 2),
        )


class ComplianceMiddleware(BaseHTTPMiddleware):
    """Enforce compliance controls on all API requests.

    Responsibilities:
    - Audit-log every request for SOC 2 / HIPAA traceability
    - Scan response bodies for PII when configured
    - Add compliance response headers
    - Block requests to sensitive paths without required metadata
    """

    def __init__(
        self,
        app: Any,
        *,
        pii_detector: PIIDetector | None = None,
        security_logger: SecurityAuditLogger | None = None,
        frameworks: Sequence[str] | None = None,
        block_pii_leaks: bool = False,
    ) -> None:
        super().__init__(app)
        self._pii_detector = pii_detector or PIIDetector()
        self._security_logger = security_logger or SecurityAuditLogger()
        self._frameworks = list(frameworks or ["soc2"])
        self._block_pii_leaks = block_pii_leaks

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Skip exempt paths
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        start = time.monotonic()

        # Extract identity metadata (set by upstream auth middleware)
        request_id = getattr(request.state, "request_id", "unknown")
        user_id = getattr(request.state, "user_id", None)
        tenant_id = getattr(request.state, "organization_id", None)

        # Process the request
        response = await call_next(request)

        duration_ms = (time.monotonic() - start) * 1000

        # PII scan on response body for sensitive paths
        pii_detected = False
        if self._is_sensitive_path(request.url.path):
            # Read the full body from the streaming response so we can scan it
            response_body = b""
            async for chunk in response.body_iterator:  # type: ignore[union-attr,attr-defined]
                if isinstance(chunk, str):
                    response_body += chunk.encode("utf-8")
                else:
                    response_body += chunk

            pii_detected = self._pii_detector.has_pii(
                response_body.decode("utf-8", errors="ignore")
            )

            if pii_detected and self._block_pii_leaks:
                await self._security_logger.log_request(
                    request_id=request_id,
                    method=request.method,
                    path=request.url.path,
                    user_id=user_id,
                    tenant_id=tenant_id,
                    frameworks=self._frameworks,
                    pii_detected=True,
                    status_code=451,
                    duration_ms=duration_ms,
                )
                return JSONResponse(
                    status_code=451,
                    content={
                        "error": "compliance_violation",
                        "detail": "Response contains PII that cannot be transmitted",
                    },
                )

            # Rebuild the response with the consumed body
            response = Response(
                content=response_body,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )

        # Add compliance headers
        for header, value in COMPLIANCE_HEADERS.items():
            response.headers[header] = value

        # Framework-specific headers
        if "hipaa" in self._frameworks:
            response.headers["X-HIPAA-Compliant"] = "true"
        if "pci_dss" in self._frameworks:
            response.headers["X-PCI-DSS-Compliant"] = "true"

        # Audit log
        await self._security_logger.log_request(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            user_id=user_id,
            tenant_id=tenant_id,
            frameworks=self._frameworks,
            pii_detected=pii_detected,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )

        return response

    @staticmethod
    def _is_sensitive_path(path: str) -> bool:
        """Check if the request path touches sensitive data."""
        return any(path.startswith(prefix) for prefix in SENSITIVE_PATH_PREFIXES)
