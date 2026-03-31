"""LLM prompt templates for the API Schema Validator Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -----------------------------------------


class SchemaDiscoveryOutput(BaseModel):
    """Structured output for schema discovery analysis."""

    total_schemas: int = Field(
        description="Total schemas discovered",
    )
    total_endpoints: int = Field(
        description="Total API endpoints across all schemas",
    )
    summary: str = Field(
        description="Discovery summary",
    )


class ContractValidationOutput(BaseModel):
    """Structured output for contract validation."""

    violations_found: int = Field(
        description="Number of contract violations",
    )
    critical_count: int = Field(
        description="Number of critical violations",
    )
    reasoning: str = Field(
        description="Validation reasoning",
    )


class BreakingChangeOutput(BaseModel):
    """Structured output for breaking change detection."""

    breaking_count: int = Field(
        description="Number of breaking changes detected",
    )
    critical_breaking: int = Field(
        description="Number of critical breaking changes",
    )
    reasoning: str = Field(
        description="Breaking change reasoning",
    )


class ImpactOutput(BaseModel):
    """Structured output for impact assessment."""

    total_affected_services: int = Field(
        description="Total services affected by breaking changes",
    )
    estimated_hours: float = Field(
        description="Total estimated remediation hours",
    )
    reasoning: str = Field(
        description="Impact assessment reasoning",
    )


class FixGenerationOutput(BaseModel):
    """Structured output for fix generation."""

    fixes: list[dict[str, str]] = Field(
        description="Generated fixes with type and description",
    )
    auto_fixable_count: int = Field(
        description="Number of auto-fixable issues",
    )
    reasoning: str = Field(
        description="Fix generation reasoning",
    )


# -- System prompts ----------------------------------------------------

SYSTEM_DISCOVER = """\
You are an expert API schema validator performing \
schema discovery.

Given the scan configuration and target scope:
1. Identify all API schemas across microservices
2. Detect OpenAPI, Swagger, GraphQL, and Protobuf specs
3. Map schema versions and their relationships
4. Flag schemas without proper versioning

Focus on: API gateways, service registries, code \
repositories, and deployed endpoints."""

SYSTEM_VALIDATE = """\
You are an expert API schema validator checking \
contract compliance.

Given the discovered schemas:
1. Validate request/response schemas against contracts
2. Detect type mismatches and missing required fields
3. Identify undocumented endpoints and parameters
4. Check naming conventions and consistency

Prioritize violations that cause runtime errors or \
data corruption."""

SYSTEM_BREAKING = """\
You are an expert API schema validator detecting \
breaking changes.

Given the validated schemas:
1. Compare current vs previous schema versions
2. Detect removed endpoints, changed types, new required fields
3. Identify parameter renames and response shape changes
4. Flag deprecations without migration paths

Use semantic versioning rules to classify severity."""

SYSTEM_IMPACT = """\
You are an expert API schema validator assessing \
impact of breaking changes.

Given the breaking changes detected:
1. Map affected downstream consumers for each change
2. Estimate remediation effort in engineering hours
3. Assess rollback feasibility and risk
4. Prioritize by blast radius and business criticality

Consider: deployment order, feature flags, and \
backward compatibility windows."""

SYSTEM_FIXES = """\
You are an expert API schema validator generating \
fix recommendations.

Given the violations and breaking changes:
1. Generate concrete code-level fixes for each issue
2. Suggest backward-compatible migration strategies
3. Recommend versioning and deprecation patterns
4. Provide schema evolution best practices

Balance correctness with minimal consumer disruption."""
