"""OTel Semantic Conventions Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class ConventionScope(StrEnum):
    RESOURCE = "resource"
    SPAN = "span"
    METRIC = "metric"
    LOG = "log"


class ViolationSeverity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ConventionStatus(StrEnum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class ConventionRule(BaseModel):
    """A single OTel semantic convention rule to validate against."""

    scope: ConventionScope = ConventionScope.RESOURCE
    attribute_name: str = ""
    expected_pattern: str = ""
    description: str = ""


class Violation(BaseModel):
    """A single semantic convention violation found in a service."""

    service: str = ""
    scope: ConventionScope = ConventionScope.RESOURCE
    attribute_name: str = ""
    actual_value: str = ""
    expected: str = ""
    severity: ViolationSeverity = ViolationSeverity.WARNING
    fix_suggestion: str = ""


class ComplianceResult(BaseModel):
    """Compliance scan result for a single service."""

    service: str = ""
    total_attributes: int = 0
    compliant_count: int = 0
    violations: list[Violation] = Field(default_factory=list)
    score: float = 0.0


class OTelSemanticState(BaseModel):
    """Main state for the OTel Semantic Conventions agent graph."""

    request_id: str = ""
    target_services: list[str] = Field(default_factory=list)
    rules: list[ConventionRule] = Field(default_factory=list)
    results: list[ComplianceResult] = Field(default_factory=list)
    overall_score: float = 0.0
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
