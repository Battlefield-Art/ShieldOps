"""State models for the Web App Scanner Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ScannerStage(StrEnum):
    """Stages of the web application scan."""

    discover_endpoints = "discover_endpoints"
    crawl_application = "crawl_application"
    test_injection = "test_injection"
    test_authentication = "test_authentication"
    test_access_control = "test_access_control"
    report = "report"


class VulnCategory(StrEnum):
    """OWASP-aligned vulnerability categories."""

    sqli = "sqli"
    xss = "xss"
    ssrf = "ssrf"
    idor = "idor"
    auth_bypass = "auth_bypass"
    csrf = "csrf"
    open_redirect = "open_redirect"
    info_disclosure = "info_disclosure"
    security_misconfig = "security_misconfig"
    broken_crypto = "broken_crypto"


class TestResult(StrEnum):
    """Result of a vulnerability test."""

    vulnerable = "vulnerable"
    potentially_vulnerable = "potentially_vulnerable"
    not_vulnerable = "not_vulnerable"
    error = "error"


class WebEndpoint(BaseModel):
    """A discovered web endpoint."""

    url: str = ""
    method: str = "GET"
    parameters: list[str] = Field(default_factory=list)
    auth_required: bool = False
    content_type: str = ""


class CrawlResult(BaseModel):
    """Result of crawling a web application."""

    url: str = ""
    status_code: int = 0
    links_found: list[str] = Field(default_factory=list)
    forms_found: int = 0
    headers: dict[str, str] = Field(default_factory=dict)


class InjectionTest(BaseModel):
    """Result of an injection test."""

    endpoint: str = ""
    parameter: str = ""
    category: str = VulnCategory.sqli
    result: str = TestResult.not_vulnerable
    payload: str = ""
    evidence: str = ""


class AuthTest(BaseModel):
    """Result of an authentication test."""

    endpoint: str = ""
    test_type: str = ""
    result: str = TestResult.not_vulnerable
    evidence: str = ""


class AccessControlTest(BaseModel):
    """Result of an access control test."""

    endpoint: str = ""
    test_type: str = ""
    result: str = TestResult.not_vulnerable
    expected_role: str = ""
    actual_access: bool = False


class WebAppScannerState(BaseModel):
    """Full state for the web app scanner workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: ScannerStage = ScannerStage.discover_endpoints

    # Input
    target_url: str = ""
    auth_config: dict[str, Any] = Field(default_factory=dict)
    scan_depth: int = 3

    # Pipeline
    endpoints_discovered: list[dict[str, Any]] = Field(default_factory=list)
    pages_crawled: list[dict[str, Any]] = Field(default_factory=list)
    injection_findings: list[dict[str, Any]] = Field(default_factory=list)
    auth_findings: list[dict[str, Any]] = Field(default_factory=list)
    access_control_findings: list[dict[str, Any]] = Field(default_factory=list)

    # Output
    owasp_coverage: dict[str, Any] = Field(default_factory=dict)
    report_summary: dict[str, Any] = Field(default_factory=dict)
    security_score: float = 0.0

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
