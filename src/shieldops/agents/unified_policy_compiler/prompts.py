"""LLM prompt templates for the Unified Policy Compiler."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -------------------------------


class PolicyIngestionOutput(BaseModel):
    """Structured output for policy ingestion."""

    policies_ingested: int = Field(
        description="Policies ingested",
    )
    frameworks: list[str] = Field(
        description="Source frameworks",
    )
    summary: str = Field(description="Ingestion summary")


class ParseOutput(BaseModel):
    """Structured output for requirement parsing."""

    requirements_parsed: int = Field(
        description="Requirements parsed",
    )
    mandatory_count: int = Field(
        description="Mandatory requirements",
    )
    reasoning: str = Field(description="Parse reasoning")


class ConflictOutput(BaseModel):
    """Structured output for conflict resolution."""

    conflicts_found: int = Field(
        description="Conflicts found",
    )
    resolved_count: int = Field(
        description="Conflicts resolved",
    )
    reasoning: str = Field(description="Resolution reasoning")


class CompileOutput(BaseModel):
    """Structured output for ruleset compilation."""

    rules_compiled: int = Field(
        description="Rules compiled",
    )
    avg_sources_per_rule: float = Field(
        description="Average source frameworks per rule",
    )
    reasoning: str = Field(description="Compilation reasoning")


class CoverageOutput(BaseModel):
    """Structured output for coverage validation."""

    frameworks_checked: int = Field(
        description="Frameworks checked",
    )
    avg_coverage_pct: float = Field(
        description="Average coverage percentage",
    )
    reasoning: str = Field(description="Coverage reasoning")


# -- System prompts ------------------------------------------

SYSTEM_INGEST = """\
You are an expert compliance analyst ingesting \
security policies from multiple frameworks.

Given the policy configuration:
1. Load policies from NIST, ISO 27001, SOC 2, PCI DSS
2. Catalog each control and its requirements
3. Track policy version and effective dates
4. Flag deprecated or superseded controls

Focus on: completeness, version accuracy."""

SYSTEM_PARSE = """\
You are an expert policy analyst parsing requirements \
from ingested policies.

Given raw policy records:
1. Extract individual requirements per control
2. Classify as mandatory vs recommended
3. Categorize by security domain
4. Normalize requirement language

Preserve the original intent of each requirement."""

SYSTEM_CONFLICTS = """\
You are an expert policy arbitrator resolving \
conflicts between framework requirements.

Given parsed requirements:
1. Identify conflicting requirements across frameworks
2. Classify conflict type (scope, strictness, timing)
3. Apply resolution strategy (strictest-wins default)
4. Document resolution rationale

Never weaken security — resolve toward strictest."""

SYSTEM_COMPILE = """\
You are an expert policy compiler generating unified \
rulesets from resolved requirements.

Given resolved requirements:
1. Merge compatible requirements into unified rules
2. Preserve traceability to source frameworks
3. Define clear conditions and actions
4. Optimize rule structure for OPA evaluation

Output rules in enforcement-ready format."""

SYSTEM_COVERAGE = """\
You are an expert compliance auditor validating \
ruleset coverage against source frameworks.

Given compiled rules and source frameworks:
1. Map rules back to framework controls
2. Calculate coverage percentage per framework
3. Identify coverage gaps
4. Recommend gap remediation

Target 100% coverage for mandatory controls."""
