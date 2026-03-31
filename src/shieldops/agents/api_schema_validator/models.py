"""State models for the API Schema Validator Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ----------------------------------------------------------


class ASVStage(StrEnum):
    """Workflow stages for API schema validation."""

    DISCOVER_SCHEMAS = "discover_schemas"
    VALIDATE_CONTRACTS = "validate_contracts"
    DETECT_BREAKING = "detect_breaking"
    ASSESS_IMPACT = "assess_impact"
    GENERATE_FIXES = "generate_fixes"
    REPORT = "report"


class SchemaFormat(StrEnum):
    """Supported API schema formats."""

    OPENAPI_3 = "openapi_3"
    OPENAPI_31 = "openapi_31"
    SWAGGER_2 = "swagger_2"
    JSON_SCHEMA = "json_schema"
    GRAPHQL = "graphql"
    PROTOBUF = "protobuf"
    ASYNCAPI = "asyncapi"


class BreakingSeverity(StrEnum):
    """Severity of a breaking change."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# -- Domain Models -----------------------------------------------------


class DiscoveredSchema(BaseModel):
    """An API schema discovered during scanning."""

    schema_id: str = ""
    service_name: str = ""
    version: str = ""
    format: SchemaFormat = SchemaFormat.OPENAPI_3
    endpoint_count: int = 0
    last_updated: datetime | None = None
    url: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContractViolation(BaseModel):
    """A contract violation detected during validation."""

    violation_id: str = ""
    schema_id: str = ""
    path: str = ""
    method: str = ""
    violation_type: str = ""
    message: str = ""
    severity: BreakingSeverity = BreakingSeverity.MEDIUM


class BreakingChange(BaseModel):
    """A breaking change detected between schema versions."""

    change_id: str = ""
    schema_id: str = ""
    path: str = ""
    change_type: str = ""
    old_value: str = ""
    new_value: str = ""
    severity: BreakingSeverity = BreakingSeverity.HIGH
    consumers_affected: int = 0


class ImpactAssessment(BaseModel):
    """Impact assessment for a breaking change."""

    change_id: str = ""
    affected_services: list[str] = Field(default_factory=list)
    estimated_effort_hours: float = 0.0
    rollback_possible: bool = True
    reasoning: str = ""


class SuggestedFix(BaseModel):
    """A suggested fix for a contract violation or breaking change."""

    fix_id: str = ""
    target_id: str = ""
    fix_type: str = ""
    description: str = ""
    code_snippet: str = ""
    confidence: float = 0.0


# -- Reasoning + State -------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the validator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class APISchemaValidatorState(BaseModel):
    """Full state for the API Schema Validator workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: ASVStage = ASVStage.DISCOVER_SCHEMAS
    config: dict[str, Any] = Field(default_factory=dict)

    # Discovery
    discovered_schemas: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_endpoints: int = 0

    # Validation
    contract_violations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    violation_count: int = 0

    # Breaking changes
    breaking_changes: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    critical_breaking_count: int = 0

    # Impact
    impact_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Fixes
    suggested_fixes: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
