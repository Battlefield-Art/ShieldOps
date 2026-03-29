"""DAST Runner Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DASTStage(StrEnum):
    DISCOVER_ENDPOINTS = "discover_endpoints"
    CRAWL_APPLICATION = "crawl_application"
    TEST_AUTHENTICATION = "test_authentication"
    FUZZ_PARAMETERS = "fuzz_parameters"
    ANALYZE_RESPONSES = "analyze_responses"
    REPORT = "report"


class AttackType(StrEnum):
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"
    SSRF = "ssrf"
    SQLI = "sqli"
    XSS = "xss"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    HEADER_INJECTION = "header_injection"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    BROKEN_ACCESS = "broken_access"


class ScanScope(StrEnum):
    FULL = "full"
    AUTH_ONLY = "auth_only"
    API_ONLY = "api_only"
    FORMS_ONLY = "forms_only"
    PASSIVE = "passive"


class CrawlResult(BaseModel):
    """Result from crawling a web application."""

    id: str = ""
    url: str = ""
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    response_size: int = 0
    has_forms: bool = False
    has_auth: bool = False
    parameters: list[str] = Field(default_factory=list)
    headers_of_interest: list[str] = Field(default_factory=list)


class EndpointFinding(BaseModel):
    """A vulnerability finding from DAST testing."""

    id: str = ""
    url: str = ""
    method: str = "GET"
    attack_type: AttackType = AttackType.SQLI
    severity: str = "medium"
    title: str = ""
    description: str = ""
    evidence: str = ""
    request_payload: str = ""
    response_snippet: str = ""
    confidence: float = 0.0
    is_confirmed: bool = False
    cwe_id: str = ""
    owasp_id: str = ""
    remediation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class DASTRunnerState(BaseModel):
    """Full state for the DAST Runner agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: DASTStage = DASTStage.DISCOVER_ENDPOINTS
    target_url: str = ""
    scan_scope: ScanScope = ScanScope.FULL
    crawl_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_endpoints: int = 0
    auth_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    fuzz_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    all_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_findings: int = 0
    critical_count: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
