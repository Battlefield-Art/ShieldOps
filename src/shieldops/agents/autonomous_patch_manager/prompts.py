"""LLM prompt templates and response schemas for the
Autonomous Patch Manager Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class InventoryScanOutput(BaseModel):
    """Structured output for asset inventory scan."""

    assets: list[dict[str, str]] = Field(
        description="Scanned assets with hostname, OS, and patch status",
    )
    outdated_count: int = Field(
        description="Number of assets with pending patches",
    )
    recommendations: list[str] = Field(
        description="Prioritized patching recommendations",
    )
    confidence: float = Field(
        description="Scan confidence score 0-1",
    )


class RiskAnalysisOutput(BaseModel):
    """Structured output for patch risk assessment."""

    risk_score: float = Field(
        description="Overall risk score 0-10",
    )
    high_risk_patches: list[str] = Field(
        description="Patches requiring manual approval",
    )
    safe_patches: list[str] = Field(
        description="Patches safe for auto-deployment",
    )
    summary: str = Field(
        description="Risk assessment summary",
    )


class DeploymentPlanOutput(BaseModel):
    """Structured output for deployment scheduling."""

    schedule: list[dict[str, str]] = Field(
        description="Deployment schedule with asset groups and windows",
    )
    strategy: str = Field(
        description="Recommended deployment strategy",
    )
    rollback_plan: str = Field(
        description="Rollback plan if deployment fails",
    )
    estimated_duration: str = Field(
        description="Estimated deployment duration",
    )


class PatchReportOutput(BaseModel):
    """Structured output for final patch report."""

    executive_summary: str = Field(
        description="Executive summary for leadership",
    )
    patches_applied: int = Field(
        description="Total patches successfully applied",
    )
    recommendations: list[str] = Field(
        description="Post-deployment recommendations",
    )
    compliance_impact: str = Field(
        description="Compliance posture impact assessment",
    )


# --- System prompts ---


SYSTEM_INVENTORY = """\
You are an expert patch management engineer analyzing \
asset inventory scan results.

Given the scanned infrastructure inventory:
1. Identify assets with critical missing patches
2. Prioritize by CVE severity and exploitability
3. Flag end-of-life systems requiring upgrade paths
4. Recommend patching order based on blast radius

Focus on OS patches, application updates, and firmware \
across Linux, Windows, and container runtimes."""


SYSTEM_RISK = """\
You are an expert patch risk analyst assessing \
deployment safety for pending patches.

Given the available patches and target infrastructure:
1. Assess compatibility risks and dependency conflicts
2. Identify patches requiring reboot or service restart
3. Score rollback feasibility for each patch
4. Classify patches as safe-auto vs manual-approval

Err on the side of caution for production systems."""


SYSTEM_SCHEDULE = """\
You are an expert deployment planner designing patch \
rollout schedules with minimal disruption.

Given the risk assessments and target environments:
1. Group patches by compatibility and environment
2. Design canary deployment with staged rollout
3. Schedule within maintenance windows when possible
4. Plan rollback triggers and recovery procedures

Balance speed of remediation against service stability."""


SYSTEM_REPORT = """\
You are an expert patch management reporter synthesizing \
deployment results and compliance impact.

Given the full patch cycle (inventory, risk, deployment):
1. Produce an executive summary for IT leadership
2. Report deployment success rates and failures
3. Assess compliance posture improvement
4. Recommend next actions for remaining gaps

Write clearly for both security and operations teams."""
