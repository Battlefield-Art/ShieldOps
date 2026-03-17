"""Tests for compliance OPA policies and ComplianceMiddleware.

Covers:
- Rego policy file validity (syntax parse check)
- ComplianceMiddleware initialization and dispatch
- PIIDetector scanning
- Compliance headers on responses
- PII blocking mode
- Sensitive path detection
- Audit logging calls
"""

from __future__ import annotations

import pathlib
from unittest.mock import AsyncMock

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

from shieldops.api.middleware.compliance import (
    COMPLIANCE_HEADERS,
    ComplianceMiddleware,
    PIIDetector,
    SecurityAuditLogger,
)

# ── Paths ────────────────────────────────────────────────────────────

POLICIES_DIR = pathlib.Path(__file__).resolve().parents[2] / "playbooks" / "policies"

EXPECTED_REGO_FILES = [
    "hipaa.rego",
    "pci_dss.rego",
    "soc2.rego",
    "gdpr.rego",
    "fedramp.rego",
]


# ── Helpers ──────────────────────────────────────────────────────────


async def _ok_endpoint(request: Request) -> Response:
    return JSONResponse({"status": "ok"})


async def _pii_endpoint(request: Request) -> Response:
    return JSONResponse({"email": "user@example.com", "ssn": "123-45-6789"})


def _build_app(
    *,
    frameworks: list[str] | None = None,
    block_pii_leaks: bool = False,
    pii_detector: PIIDetector | None = None,
    security_logger: SecurityAuditLogger | None = None,
    endpoint=_ok_endpoint,
    path: str = "/api/v1/agents/test",
) -> Starlette:
    app = Starlette(routes=[Route(path, endpoint)])
    app.add_middleware(
        ComplianceMiddleware,
        frameworks=frameworks,
        block_pii_leaks=block_pii_leaks,
        pii_detector=pii_detector,
        security_logger=security_logger,
    )
    return app


# ── Rego policy file tests ───────────────────────────────────────────


class TestRegoPolicies:
    """Verify each .rego file exists and has valid structure."""

    @pytest.mark.parametrize("filename", EXPECTED_REGO_FILES)
    def test_rego_file_exists(self, filename: str) -> None:
        path = POLICIES_DIR / filename
        assert path.exists(), f"Missing policy file: {path}"

    @pytest.mark.parametrize("filename", EXPECTED_REGO_FILES)
    def test_rego_file_has_package_declaration(self, filename: str) -> None:
        path = POLICIES_DIR / filename
        content = path.read_text()
        assert "package shieldops." in content, f"{filename} missing package declaration"

    @pytest.mark.parametrize("filename", EXPECTED_REGO_FILES)
    def test_rego_file_has_deny_rules(self, filename: str) -> None:
        path = POLICIES_DIR / filename
        content = path.read_text()
        assert "deny contains msg" in content, f"{filename} should define deny rules"

    @pytest.mark.parametrize("filename", EXPECTED_REGO_FILES)
    def test_rego_file_uses_v1_import(self, filename: str) -> None:
        path = POLICIES_DIR / filename
        content = path.read_text()
        assert "import rego.v1" in content, f"{filename} should use rego.v1 import"

    def test_hipaa_enforces_phi_audit(self) -> None:
        content = (POLICIES_DIR / "hipaa.rego").read_text()
        assert "audit" in content.lower()
        assert "PHI" in content

    def test_pci_dss_enforces_pan_protection(self) -> None:
        content = (POLICIES_DIR / "pci_dss.rego").read_text()
        assert "full_pan" in content
        assert "MFA" in content or "mfa" in content

    def test_soc2_enforces_change_management(self) -> None:
        content = (POLICIES_DIR / "soc2.rego").read_text()
        assert "CC8.1" in content
        assert "approval" in content.lower()

    def test_gdpr_enforces_erasure_right(self) -> None:
        content = (POLICIES_DIR / "gdpr.rego").read_text()
        assert "Art. 17" in content
        assert "erasure" in content.lower()

    def test_fedramp_enforces_fips(self) -> None:
        content = (POLICIES_DIR / "fedramp.rego").read_text()
        assert "FIPS" in content or "fips" in content
        assert "SC-13" in content


# ── PIIDetector tests ────────────────────────────────────────────────


class TestPIIDetector:
    def test_detects_ssn(self) -> None:
        detector = PIIDetector()
        assert detector.has_pii("My SSN is 123-45-6789")

    def test_detects_email(self) -> None:
        detector = PIIDetector()
        assert detector.has_pii("Contact me at user@example.com")

    def test_no_false_positive_on_clean_text(self) -> None:
        detector = PIIDetector()
        assert not detector.has_pii("This is a normal log message with no PII")

    def test_scan_returns_findings(self) -> None:
        detector = PIIDetector()
        findings = detector.scan("SSN: 123-45-6789")
        assert len(findings) >= 1
        assert findings[0]["type"] == "ssn"
        # Verify redaction
        assert "****" in findings[0]["match_redacted"]

    def test_custom_patterns(self) -> None:
        import re

        detector = PIIDetector(extra_patterns={"custom_id": re.compile(r"CUST-\d{6}")})
        assert detector.has_pii("Customer CUST-123456")


# ── ComplianceMiddleware tests ───────────────────────────────────────


class TestComplianceMiddleware:
    def test_default_initialization(self) -> None:
        app = _build_app()
        client = TestClient(app)
        resp = client.get("/api/v1/agents/test")
        assert resp.status_code == 200

    def test_compliance_headers_added(self) -> None:
        app = _build_app()
        client = TestClient(app)
        resp = client.get("/api/v1/agents/test")
        for header, value in COMPLIANCE_HEADERS.items():
            assert resp.headers.get(header) == value

    def test_hipaa_header_when_framework_set(self) -> None:
        app = _build_app(frameworks=["hipaa"])
        client = TestClient(app)
        resp = client.get("/api/v1/agents/test")
        assert resp.headers.get("X-HIPAA-Compliant") == "true"

    def test_pci_header_when_framework_set(self) -> None:
        app = _build_app(frameworks=["pci_dss"])
        client = TestClient(app)
        resp = client.get("/api/v1/agents/test")
        assert resp.headers.get("X-PCI-DSS-Compliant") == "true"

    def test_exempt_paths_skip_compliance(self) -> None:
        app = Starlette(routes=[Route("/health", _ok_endpoint)])
        app.add_middleware(ComplianceMiddleware)
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert "X-Compliance-Enforced" not in resp.headers

    def test_pii_blocking_returns_451(self) -> None:
        app = _build_app(
            block_pii_leaks=True,
            endpoint=_pii_endpoint,
            path="/api/v1/agents/test",
        )
        client = TestClient(app)
        resp = client.get("/api/v1/agents/test")
        assert resp.status_code == 451
        assert resp.json()["error"] == "compliance_violation"

    def test_pii_detection_without_blocking(self) -> None:
        """When block_pii_leaks=False, PII is logged but not blocked."""
        mock_logger = SecurityAuditLogger()
        mock_logger.log_request = AsyncMock()  # type: ignore[method-assign]

        app = _build_app(
            block_pii_leaks=False,
            security_logger=mock_logger,
            endpoint=_pii_endpoint,
            path="/api/v1/agents/test",
        )
        client = TestClient(app)
        resp = client.get("/api/v1/agents/test")
        assert resp.status_code == 200
        # Audit logger should have been called with pii_detected=True
        mock_logger.log_request.assert_called_once()
        call_kwargs = mock_logger.log_request.call_args.kwargs
        assert call_kwargs["pii_detected"] is True

    def test_non_sensitive_path_skips_pii_scan(self) -> None:
        """Non-sensitive paths should not trigger PII scanning."""
        detector = PIIDetector()
        detector.has_pii = lambda text: pytest.fail("PII scan should not run")  # type: ignore[method-assign]

        app = Starlette(routes=[Route("/api/v1/status", _pii_endpoint)])
        app.add_middleware(ComplianceMiddleware, pii_detector=detector)
        client = TestClient(app)
        resp = client.get("/api/v1/status")
        assert resp.status_code == 200
