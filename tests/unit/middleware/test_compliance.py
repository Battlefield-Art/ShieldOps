"""Behavioral TDD tests for the compliance enforcement middleware.

Covers PIIDetector (pattern matching, redaction), SecurityAuditLogger,
and ComplianceMiddleware (exempt paths, PII blocking, compliance headers,
framework headers, audit logging).
"""

from __future__ import annotations

import re
from unittest.mock import AsyncMock

import pytest
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

from shieldops.api.middleware.compliance import (
    EXEMPT_PATHS,
    ComplianceMiddleware,
    PIIDetector,
    SecurityAuditLogger,
)

# ── Helpers ──────────────────────────────────────────────────────────


async def _ok_endpoint(request: Request) -> Response:
    """Return a clean 200 response with no PII."""
    return JSONResponse({"status": "ok", "message": "all clear"})


async def _pii_endpoint(request: Request) -> Response:
    """Return a response containing PII (SSN)."""
    return JSONResponse({"ssn": "123-45-6789", "name": "Jane Doe"})


async def _email_pii_endpoint(request: Request) -> Response:
    """Return a response containing PII (email)."""
    return JSONResponse({"contact": "user@example.com"})


async def _health_endpoint(request: Request) -> Response:
    return JSONResponse({"status": "healthy"})


class StateSetter(BaseHTTPMiddleware):
    """Injects request.state fields needed by ComplianceMiddleware."""

    def __init__(
        self,
        app: object,
        *,
        request_id: str = "req-001",
        user_id: str | None = "user-1",
        organization_id: str | None = "org-1",
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._request_id = request_id
        self._user_id = user_id
        self._organization_id = organization_id

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request.state.request_id = self._request_id
        request.state.user_id = self._user_id
        request.state.organization_id = self._organization_id
        return await call_next(request)


def _build_app(
    *,
    pii_detector: PIIDetector | None = None,
    security_logger: SecurityAuditLogger | None = None,
    frameworks: list[str] | None = None,
    block_pii_leaks: bool = False,
    use_pii_endpoint: bool = False,
    use_email_pii_endpoint: bool = False,
) -> Starlette:
    """Build a minimal Starlette app with the ComplianceMiddleware."""
    if use_pii_endpoint:
        handler = _pii_endpoint
    elif use_email_pii_endpoint:
        handler = _email_pii_endpoint
    else:
        handler = _ok_endpoint

    app = Starlette(
        routes=[
            Route("/health", _health_endpoint),
            Route("/ready", _health_endpoint),
            Route("/metrics", _health_endpoint),
            Route("/api/v1/agents/list", handler),
            Route("/api/v1/security/scan", handler),
            Route("/api/v1/billing/usage", handler),
            Route("/api/v1/compliance/report", handler),
            Route("/api/v1/remediation/run", handler),
            Route("/api/v1/dashboard/overview", _ok_endpoint),
        ],
    )

    # ComplianceMiddleware is the outermost so it sees the response body
    app.add_middleware(
        ComplianceMiddleware,
        pii_detector=pii_detector or PIIDetector(),
        security_logger=security_logger,
        frameworks=frameworks,
        block_pii_leaks=block_pii_leaks,
    )
    # StateSetter runs before compliance so request.state is populated
    app.add_middleware(StateSetter)

    return app


# ── PIIDetector Tests ────────────────────────────────────────────────


class TestPIIDetector:
    """Feature: PIIDetector scans text for PII patterns and redacts matches."""

    @pytest.fixture()
    def detector(self) -> PIIDetector:
        return PIIDetector()

    # -- Detection -------------------------------------------------------

    def test_scan_detects_ssn_pattern(self, detector: PIIDetector) -> None:
        """Given text containing an SSN,
        when scanned,
        then the finding has type 'ssn' with a redacted match."""
        findings = detector.scan("My SSN is 123-45-6789 thanks")
        assert len(findings) >= 1
        ssn_findings = [f for f in findings if f["type"] == "ssn"]
        assert len(ssn_findings) == 1
        assert ssn_findings[0]["match_redacted"].endswith("6789")
        assert ssn_findings[0]["match_redacted"].startswith("*")

    def test_scan_detects_email_pattern(self, detector: PIIDetector) -> None:
        """Given text containing an email address,
        when scanned,
        then a finding of type 'email' is returned."""
        findings = detector.scan("Contact alice@example.com for info")
        email_findings = [f for f in findings if f["type"] == "email"]
        assert len(email_findings) == 1
        assert email_findings[0]["match_redacted"].endswith(".com")

    def test_scan_detects_credit_card_pattern(self, detector: PIIDetector) -> None:
        """Given text containing a credit card number,
        when scanned,
        then a finding of type 'credit_card' is returned."""
        findings = detector.scan("Card: 4111111111111111")
        cc_findings = [f for f in findings if f["type"] == "credit_card"]
        assert len(cc_findings) >= 1

    def test_scan_detects_us_phone_pattern(self, detector: PIIDetector) -> None:
        """Given text containing a US phone number,
        when scanned,
        then a finding of type 'phone_us' is returned."""
        findings = detector.scan("Call me at 555-123-4567")
        phone_findings = [f for f in findings if f["type"] == "phone_us"]
        assert len(phone_findings) == 1

    def test_scan_returns_empty_list_for_clean_text(self, detector: PIIDetector) -> None:
        """Given text with no PII patterns,
        when scanned,
        then an empty list is returned."""
        findings = detector.scan("This text has no personal information whatsoever")
        assert findings == []

    def test_scan_handles_empty_string(self, detector: PIIDetector) -> None:
        """Given an empty string, scan returns no findings."""
        assert detector.scan("") == []

    # -- has_pii ---------------------------------------------------------

    def test_has_pii_returns_true_when_pii_present(self, detector: PIIDetector) -> None:
        """Given text with PII, has_pii returns True."""
        assert detector.has_pii("SSN: 123-45-6789") is True

    def test_has_pii_returns_false_when_no_pii(self, detector: PIIDetector) -> None:
        """Given clean text, has_pii returns False."""
        assert detector.has_pii("Just a normal string") is False

    def test_has_pii_returns_false_for_empty_string(self, detector: PIIDetector) -> None:
        assert detector.has_pii("") is False

    # -- Redaction -------------------------------------------------------

    def test_redact_masks_all_but_last_four_chars(self) -> None:
        """Given a value longer than 4 chars,
        _redact replaces all but the last 4 with asterisks."""
        result = PIIDetector._redact("123-45-6789")
        assert result == "*******6789"

    def test_redact_fully_masks_short_values(self) -> None:
        """Given a value with 4 or fewer chars,
        _redact returns '****'."""
        assert PIIDetector._redact("AB") == "****"
        assert PIIDetector._redact("ABCD") == "****"

    def test_redact_boundary_five_chars(self) -> None:
        """A 5-char value gets 1 asterisk prefix + last 4 chars."""
        assert PIIDetector._redact("12345") == "*2345"

    # -- Extra patterns --------------------------------------------------

    def test_extra_patterns_are_detected(self) -> None:
        """Given a PIIDetector with extra_patterns,
        when text matches the custom pattern,
        then a finding is returned."""
        passport_pattern = re.compile(r"\b[A-Z]{2}\d{7}\b")
        detector = PIIDetector(extra_patterns={"passport": passport_pattern})
        findings = detector.scan("Passport: AB1234567")
        passport_findings = [f for f in findings if f["type"] == "passport"]
        assert len(passport_findings) == 1
        assert passport_findings[0]["match_redacted"].endswith("4567")

    def test_extra_patterns_coexist_with_defaults(self) -> None:
        """Extra patterns augment (not replace) default patterns."""
        detector = PIIDetector(extra_patterns={"custom": re.compile(r"CUSTOM-\d+")})
        # Default SSN detection still works
        assert detector.has_pii("SSN: 123-45-6789") is True
        # Custom pattern also works
        findings = detector.scan("ref CUSTOM-999")
        assert any(f["type"] == "custom" for f in findings)

    def test_multiple_matches_same_type(self, detector: PIIDetector) -> None:
        """Multiple SSNs in the same text produce multiple findings."""
        text = "SSN1: 111-22-3333 and SSN2: 444-55-6666"
        ssn_findings = [f for f in detector.scan(text) if f["type"] == "ssn"]
        assert len(ssn_findings) == 2


# ── SecurityAuditLogger Tests ────────────────────────────────────────


class TestSecurityAuditLogger:
    """Feature: SecurityAuditLogger emits structured audit events."""

    @pytest.mark.asyncio
    async def test_log_request_does_not_raise(self) -> None:
        """Given valid parameters, log_request completes without error."""
        audit_logger = SecurityAuditLogger()
        await audit_logger.log_request(
            request_id="req-1",
            method="GET",
            path="/api/v1/agents/list",
            user_id="user-1",
            tenant_id="org-1",
            frameworks=["soc2"],
            pii_detected=False,
            status_code=200,
            duration_ms=12.5,
        )
        # No exception means success; structured log was emitted

    @pytest.mark.asyncio
    async def test_log_request_accepts_none_identity(self) -> None:
        """Audit logger handles None user_id and tenant_id gracefully."""
        audit_logger = SecurityAuditLogger()
        await audit_logger.log_request(
            request_id="req-2",
            method="POST",
            path="/api/v1/security/scan",
            user_id=None,
            tenant_id=None,
            frameworks=["hipaa"],
            pii_detected=True,
            status_code=451,
            duration_ms=3.14159,
        )


# ── ComplianceMiddleware Tests ───────────────────────────────────────


class TestComplianceMiddlewareExemptPaths:
    """Feature: Health, readiness, and metrics paths bypass compliance checks."""

    @pytest.fixture()
    def mock_logger(self) -> AsyncMock:
        logger = AsyncMock(spec=SecurityAuditLogger)
        logger.log_request = AsyncMock()
        return logger

    @pytest.mark.parametrize("exempt_path", ["/health", "/ready", "/metrics"])
    def test_exempt_path_skips_compliance_headers(
        self, exempt_path: str, mock_logger: AsyncMock
    ) -> None:
        """Given a request to an exempt path,
        when processed by the middleware,
        then no compliance headers are added and audit logger is not called."""
        app = _build_app(security_logger=mock_logger)
        client = TestClient(app)

        response = client.get(exempt_path)

        assert response.status_code == 200
        assert "X-Compliance-Enforced" not in response.headers
        assert "X-Data-Classification" not in response.headers
        mock_logger.log_request.assert_not_called()

    def test_exempt_paths_constant_matches_expected(self) -> None:
        """Verify the EXEMPT_PATHS constant contains the expected paths."""
        assert frozenset({"/health", "/ready", "/metrics"}) == EXEMPT_PATHS


class TestComplianceMiddlewareHeaders:
    """Feature: Non-exempt responses receive compliance and framework headers."""

    @pytest.fixture()
    def mock_logger(self) -> AsyncMock:
        logger = AsyncMock(spec=SecurityAuditLogger)
        logger.log_request = AsyncMock()
        return logger

    def test_non_sensitive_path_gets_compliance_headers(self, mock_logger: AsyncMock) -> None:
        """Given a request to a non-sensitive, non-exempt path,
        when processed by the middleware,
        then standard compliance headers are added."""
        app = _build_app(security_logger=mock_logger)
        client = TestClient(app)

        response = client.get("/api/v1/dashboard/overview")

        assert response.status_code == 200
        assert response.headers["X-Compliance-Enforced"] == "true"
        assert response.headers["X-Data-Classification"] == "internal"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Pragma"] == "no-cache"

    def test_sensitive_path_without_pii_gets_compliance_headers(
        self, mock_logger: AsyncMock
    ) -> None:
        """Given a request to a sensitive path with a clean response body,
        when processed by the middleware,
        then compliance headers are present and response passes through."""
        app = _build_app(security_logger=mock_logger, block_pii_leaks=True)
        client = TestClient(app)

        response = client.get("/api/v1/agents/list")

        assert response.status_code == 200
        assert response.headers["X-Compliance-Enforced"] == "true"
        assert response.json()["status"] == "ok"

    def test_hipaa_framework_adds_hipaa_header(self, mock_logger: AsyncMock) -> None:
        """Given frameworks=['hipaa'],
        when the middleware processes a request,
        then X-HIPAA-Compliant header is set to 'true'."""
        app = _build_app(security_logger=mock_logger, frameworks=["hipaa"])
        client = TestClient(app)

        response = client.get("/api/v1/dashboard/overview")

        assert response.headers["X-HIPAA-Compliant"] == "true"

    def test_pci_dss_framework_adds_pci_header(self, mock_logger: AsyncMock) -> None:
        """Given frameworks=['pci_dss'],
        when the middleware processes a request,
        then X-PCI-DSS-Compliant header is set to 'true'."""
        app = _build_app(security_logger=mock_logger, frameworks=["pci_dss"])
        client = TestClient(app)

        response = client.get("/api/v1/agents/list")

        assert response.headers["X-PCI-DSS-Compliant"] == "true"

    def test_multiple_frameworks_add_multiple_headers(self, mock_logger: AsyncMock) -> None:
        """Given frameworks=['hipaa', 'pci_dss'],
        when the middleware processes a request,
        then both framework headers are present."""
        app = _build_app(
            security_logger=mock_logger,
            frameworks=["hipaa", "pci_dss"],
        )
        client = TestClient(app)

        response = client.get("/api/v1/agents/list")

        assert response.headers["X-HIPAA-Compliant"] == "true"
        assert response.headers["X-PCI-DSS-Compliant"] == "true"

    def test_default_frameworks_no_hipaa_or_pci_headers(self, mock_logger: AsyncMock) -> None:
        """Default frameworks=['soc2'] should not add HIPAA or PCI headers."""
        app = _build_app(security_logger=mock_logger)
        client = TestClient(app)

        response = client.get("/api/v1/agents/list")

        assert "X-HIPAA-Compliant" not in response.headers
        assert "X-PCI-DSS-Compliant" not in response.headers


class TestComplianceMiddlewarePIIBlocking:
    """Feature: PII in response bodies on sensitive paths can be blocked."""

    @pytest.fixture()
    def mock_logger(self) -> AsyncMock:
        logger = AsyncMock(spec=SecurityAuditLogger)
        logger.log_request = AsyncMock()
        return logger

    def test_sensitive_path_with_pii_and_blocking_returns_451(self, mock_logger: AsyncMock) -> None:
        """Given block_pii_leaks=True and a sensitive path response with PII,
        when the middleware scans the response,
        then it returns a 451 with compliance_violation error."""
        app = _build_app(
            security_logger=mock_logger,
            block_pii_leaks=True,
            use_pii_endpoint=True,
        )
        client = TestClient(app)

        response = client.get("/api/v1/agents/list")

        assert response.status_code == 451
        body = response.json()
        assert body["error"] == "compliance_violation"
        assert "PII" in body["detail"]

    def test_sensitive_path_with_pii_and_no_blocking_passes_through(
        self, mock_logger: AsyncMock
    ) -> None:
        """Given block_pii_leaks=False and a sensitive path response with PII,
        when the middleware scans the response,
        then the original response is returned with compliance headers."""
        app = _build_app(
            security_logger=mock_logger,
            block_pii_leaks=False,
            use_pii_endpoint=True,
        )
        client = TestClient(app)

        response = client.get("/api/v1/agents/list")

        assert response.status_code == 200
        assert "123-45-6789" in response.text
        assert response.headers["X-Compliance-Enforced"] == "true"

    def test_non_sensitive_path_with_pii_is_not_scanned(self, mock_logger: AsyncMock) -> None:
        """Given a non-sensitive path (e.g., /api/v1/dashboard/overview),
        even with block_pii_leaks=True,
        the response is not scanned for PII and passes through."""
        # The /dashboard/overview route always returns clean data,
        # so we verify it is not blocked even with blocking enabled
        app = _build_app(
            security_logger=mock_logger,
            block_pii_leaks=True,
        )
        client = TestClient(app)

        response = client.get("/api/v1/dashboard/overview")

        assert response.status_code == 200

    def test_pii_blocking_with_email_in_response(self, mock_logger: AsyncMock) -> None:
        """Given block_pii_leaks=True and an email in the response body,
        when scanned on a sensitive path,
        then a 451 is returned."""
        app = _build_app(
            security_logger=mock_logger,
            block_pii_leaks=True,
            use_email_pii_endpoint=True,
        )
        client = TestClient(app)

        response = client.get("/api/v1/security/scan")

        assert response.status_code == 451
        assert response.json()["error"] == "compliance_violation"

    @pytest.mark.parametrize(
        "sensitive_path",
        [
            "/api/v1/agents/list",
            "/api/v1/remediation/run",
            "/api/v1/security/scan",
            "/api/v1/billing/usage",
            "/api/v1/compliance/report",
        ],
    )
    def test_all_sensitive_path_prefixes_trigger_pii_scan(
        self, sensitive_path: str, mock_logger: AsyncMock
    ) -> None:
        """Given block_pii_leaks=True, all sensitive path prefixes
        trigger PII scanning and block when PII is found."""
        app = _build_app(
            security_logger=mock_logger,
            block_pii_leaks=True,
            use_pii_endpoint=True,
        )
        client = TestClient(app)

        response = client.get(sensitive_path)

        assert response.status_code == 451, (
            f"Expected 451 for sensitive path {sensitive_path}, got {response.status_code}"
        )


class TestComplianceMiddlewareAuditLogging:
    """Feature: Every non-exempt request is audit-logged."""

    @pytest.fixture()
    def mock_logger(self) -> AsyncMock:
        logger = AsyncMock(spec=SecurityAuditLogger)
        logger.log_request = AsyncMock()
        return logger

    def test_audit_logger_called_for_non_exempt_request(self, mock_logger: AsyncMock) -> None:
        """Given a non-exempt request,
        when processed by the middleware,
        then the security audit logger is called once."""
        app = _build_app(security_logger=mock_logger)
        client = TestClient(app)

        client.get("/api/v1/agents/list")

        mock_logger.log_request.assert_called_once()

    def test_audit_logger_receives_correct_parameters(self, mock_logger: AsyncMock) -> None:
        """The audit log call includes method, path, status_code, and pii_detected."""
        app = _build_app(security_logger=mock_logger)
        client = TestClient(app)

        client.get("/api/v1/agents/list")

        call_kwargs = mock_logger.log_request.call_args.kwargs
        assert call_kwargs["method"] == "GET"
        assert call_kwargs["path"] == "/api/v1/agents/list"
        assert call_kwargs["status_code"] == 200
        assert call_kwargs["pii_detected"] is False
        assert call_kwargs["request_id"] == "req-001"
        assert call_kwargs["user_id"] == "user-1"
        assert call_kwargs["tenant_id"] == "org-1"
        assert isinstance(call_kwargs["duration_ms"], float)
        assert call_kwargs["duration_ms"] >= 0

    def test_audit_logger_called_for_pii_blocked_request(self, mock_logger: AsyncMock) -> None:
        """When PII is blocked (451), the audit logger is called with
        status_code=451 and pii_detected=True."""
        app = _build_app(
            security_logger=mock_logger,
            block_pii_leaks=True,
            use_pii_endpoint=True,
        )
        client = TestClient(app)

        client.get("/api/v1/agents/list")

        mock_logger.log_request.assert_called_once()
        call_kwargs = mock_logger.log_request.call_args.kwargs
        assert call_kwargs["status_code"] == 451
        assert call_kwargs["pii_detected"] is True

    def test_audit_logger_records_pii_detected_when_not_blocking(
        self, mock_logger: AsyncMock
    ) -> None:
        """When PII is found but not blocked, audit log shows pii_detected=True
        with the original status code."""
        app = _build_app(
            security_logger=mock_logger,
            block_pii_leaks=False,
            use_pii_endpoint=True,
        )
        client = TestClient(app)

        client.get("/api/v1/agents/list")

        call_kwargs = mock_logger.log_request.call_args.kwargs
        assert call_kwargs["pii_detected"] is True
        assert call_kwargs["status_code"] == 200

    def test_audit_logger_not_called_for_exempt_paths(self, mock_logger: AsyncMock) -> None:
        """Exempt paths (/health, /ready, /metrics) must not be audit-logged."""
        app = _build_app(security_logger=mock_logger)
        client = TestClient(app)

        client.get("/health")
        client.get("/ready")
        client.get("/metrics")

        mock_logger.log_request.assert_not_called()

    def test_audit_logger_includes_frameworks(self, mock_logger: AsyncMock) -> None:
        """The audit log includes the configured compliance frameworks."""
        app = _build_app(
            security_logger=mock_logger,
            frameworks=["hipaa", "pci_dss"],
        )
        client = TestClient(app)

        client.get("/api/v1/agents/list")

        call_kwargs = mock_logger.log_request.call_args.kwargs
        assert call_kwargs["frameworks"] == ["hipaa", "pci_dss"]
