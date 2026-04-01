"""LLM prompt templates for the Multi-Tenant Isolation Guard."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -------------------------------


class TenantMapOutput(BaseModel):
    """Structured output for tenant mapping."""

    tenants_mapped: int = Field(
        description="Tenants mapped",
    )
    total_resources: int = Field(
        description="Total resources mapped",
    )
    summary: str = Field(description="Mapping summary")


class BoundaryScanOutput(BaseModel):
    """Structured output for boundary scanning."""

    boundaries_scanned: int = Field(
        description="Boundaries scanned",
    )
    issues_found: int = Field(
        description="Boundary issues found",
    )
    reasoning: str = Field(description="Scan reasoning")


class LeakageOutput(BaseModel):
    """Structured output for leakage detection."""

    leakages_detected: int = Field(
        description="Leakages detected",
    )
    critical_count: int = Field(
        description="Critical leakages",
    )
    reasoning: str = Field(description="Detection reasoning")


class AssessmentOutput(BaseModel):
    """Structured output for isolation assessment."""

    assessments_completed: int = Field(
        description="Assessments completed",
    )
    avg_isolation_score: float = Field(
        description="Average isolation score",
    )
    reasoning: str = Field(description="Assessment reasoning")


class EnforcementOutput(BaseModel):
    """Structured output for control enforcement."""

    controls_enforced: int = Field(
        description="Controls enforced",
    )
    actions_taken: int = Field(
        description="Enforcement actions taken",
    )
    reasoning: str = Field(description="Enforcement reasoning")


# -- System prompts ------------------------------------------

SYSTEM_MAP = """\
You are an expert multi-tenant architect mapping \
tenant resource boundaries.

Given the platform configuration:
1. Enumerate all tenants and their resources
2. Map isolation boundaries (network, data, compute)
3. Identify shared resources and services
4. Document namespace and region assignments

Focus on: completeness, shared resource visibility."""

SYSTEM_SCAN = """\
You are an expert security engineer scanning tenant \
isolation boundaries for weaknesses.

Given tenant mappings:
1. Scan network isolation (VPCs, subnets, firewalls)
2. Check data isolation (schemas, encryption, access)
3. Validate compute isolation (containers, VMs)
4. Test API-level isolation

Flag any shared pathways between tenants."""

SYSTEM_LEAKAGE = """\
You are an expert data security analyst detecting \
cross-tenant data leakage.

Given boundary scan results:
1. Detect data flowing between tenant boundaries
2. Identify shared database connections or caches
3. Check for log aggregation mixing tenant data
4. Scan for cross-tenant API access patterns

Prioritize PII and credential leakage detection."""

SYSTEM_ASSESS = """\
You are an expert compliance assessor evaluating \
overall tenant isolation quality.

Given leakage detections:
1. Score isolation quality per tenant (0-1)
2. Identify isolation gaps by type
3. Assess compliance with SOC 2 and ISO 27001
4. Recommend isolation tier improvements

Map gaps to specific compliance controls."""

SYSTEM_ENFORCE = """\
You are an expert security operator enforcing \
tenant isolation controls.

Given isolation assessments:
1. Apply network segmentation rules
2. Enforce data access policies
3. Isolate compute workloads
4. Block cross-tenant API access

Prioritize critical isolation gaps first."""
