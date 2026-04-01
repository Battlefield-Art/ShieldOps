"""LLM prompt templates for the Autonomous Patch Manager Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class InventoryScanOutput(BaseModel):
    """Structured output for inventory scanning."""

    total_assets: int = Field(description="Total assets scanned")
    outdated_count: int = Field(
        description="Assets needing patches",
    )
    summary: str = Field(description="Inventory summary")


class PatchAssessmentOutput(BaseModel):
    """Structured output for patch assessment."""

    patches_assessed: int = Field(
        description="Patches assessed",
    )
    critical_count: int = Field(
        description="Critical patches found",
    )
    avg_risk_score: float = Field(
        description="Average risk score 0-10",
    )
    reasoning: str = Field(description="Assessment reasoning")


class ScheduleOutput(BaseModel):
    """Structured output for deployment scheduling."""

    schedules_created: int = Field(
        description="Deployment schedules created",
    )
    estimated_duration: str = Field(
        description="Estimated deployment duration",
    )
    reasoning: str = Field(description="Scheduling reasoning")


class ExecutionOutput(BaseModel):
    """Structured output for patch execution."""

    patches_applied: int = Field(
        description="Patches applied",
    )
    success_rate: float = Field(
        description="Execution success rate 0-1",
    )
    reasoning: str = Field(description="Execution reasoning")


class ValidationOutput(BaseModel):
    """Structured output for result validation."""

    assets_validated: int = Field(
        description="Assets validated",
    )
    healthy_count: int = Field(description="Healthy assets")
    issues_found: int = Field(description="Issues found")
    reasoning: str = Field(description="Validation reasoning")


# ── System prompts ────────────────────────────────────

SYSTEM_SCAN_INVENTORY = """\
You are an expert patch management engineer scanning \
fleet inventory.

Given the infrastructure scope:
1. Enumerate all assets across environments
2. Identify OS versions and installed software
3. Flag end-of-life or unsupported systems
4. Record current patch levels per asset

Focus on: completeness, accuracy, OS diversity."""

SYSTEM_ASSESS_PATCHES = """\
You are an expert patch analyst assessing available \
patches for fleet deployment.

Given the asset inventory and available patches:
1. Match patches to affected assets by CVE
2. Score risk based on exploit availability
3. Assess compatibility and dependency conflicts
4. Prioritize by severity and blast radius

Err on the side of caution for production systems."""

SYSTEM_SCHEDULE = """\
You are an expert deployment planner scheduling patch \
rollouts with minimal disruption.

Given patch assessments and fleet topology:
1. Group patches by compatibility and environment
2. Design staged rollout with canary groups
3. Schedule within maintenance windows
4. Plan rollback triggers and recovery procedures

Balance speed of remediation against stability."""

SYSTEM_EXECUTE = """\
You are an expert patch deployment engineer executing \
patch installations across fleet.

Given deployment schedules:
1. Apply patches in priority order
2. Monitor health metrics during rollout
3. Trigger rollback on failure thresholds
4. Record execution results per asset

Focus on: zero-downtime, rollback safety, \
audit trail."""

SYSTEM_VALIDATE = """\
You are an expert systems validation engineer verifying \
post-patch health.

Given execution results:
1. Run health checks on patched assets
2. Verify service availability and performance
3. Confirm CVE remediation via rescan
4. Flag assets that need manual intervention

Ensure no regressions in service behavior."""
