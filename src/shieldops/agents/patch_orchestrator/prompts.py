"""LLM prompt templates for the Patch Orchestrator Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PatchPrioritizationResult(BaseModel):
    """Structured output for patch prioritization."""

    priority_order: list[str] = Field(description="Patch IDs in recommended deployment order")
    rationale: str = Field(description="Reasoning behind the prioritization")
    emergency_patches: list[str] = Field(description="Patches requiring immediate deployment")


class PatchReportResult(BaseModel):
    """Structured output for the final patch report."""

    title: str = Field(description="Report title")
    executive_summary: str = Field(description="1-2 sentence summary of patch deployment")
    risk_assessment: str = Field(description="Overall risk: low, medium, high, critical")
    recommendations: list[str] = Field(description="Follow-up recommendations")


SYSTEM_PRIORITIZE = """\
You are an expert patch management engineer. Given a list \
of patches with CVE severity, affected system count, and \
risk scores, determine the optimal deployment order.

Prioritize:
1. Emergency/critical CVEs on internet-facing systems
2. Patches affecting the most systems
3. Patches with known active exploits
4. Lower-risk patches last

Return the deployment order with rationale."""

SYSTEM_REPORT = """\
You are a patch management expert generating a deployment \
report. Summarize the patch deployment results including \
success/failure counts, rollbacks, and recommendations.

Keep the report concise and actionable for an operations \
audience."""
