"""Automated Security Testing Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TestStage(StrEnum):
    SCOPE = "scope"
    SCAN = "scan"
    ANALYZE = "analyze"
    REPORT = "report"


class TestCategory(StrEnum):
    VULNERABILITY = "vulnerability"
    CONFIGURATION = "configuration"
    NETWORK = "network"
    CREDENTIAL = "credential"
    COMPLIANCE = "compliance"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TestScope(BaseModel):
    """Defines the scope of a security testing engagement."""

    targets: list[str] = Field(default_factory=list)
    categories: list[TestCategory] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)


class SecurityFinding(BaseModel):
    """A single security finding discovered during testing."""

    finding_id: str = ""
    category: TestCategory = TestCategory.VULNERABILITY
    severity: FindingSeverity = FindingSeverity.MEDIUM
    title: str = ""
    description: str = ""
    affected_resource: str = ""
    remediation: str = ""
    risk_score: int = 0
    cve_id: str = ""


class TestReport(BaseModel):
    """Aggregated security testing report with prioritized findings."""

    scope: TestScope = Field(default_factory=TestScope)
    findings: list[SecurityFinding] = Field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    risk_score_total: int = 0
    pass_rate: float = 0.0


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityTestingState(BaseModel):
    """Main state for the Automated Security Testing agent graph."""

    request_id: str = ""
    stage: TestStage = TestStage.SCOPE

    # Scope
    scope: dict[str, Any] = Field(default_factory=dict)

    # Findings
    findings: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Recommendations
    recommendations: list[str] = Field(default_factory=list)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
