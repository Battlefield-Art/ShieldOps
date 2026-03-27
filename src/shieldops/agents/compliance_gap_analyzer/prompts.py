"""Compliance Gap Analyzer Agent — LLM prompt templates."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FrameworkMappingOutput(BaseModel):
    """LLM output for control-to-framework mapping."""

    requirement_id: str = Field(
        description="Framework requirement ID",
    )
    requirement_name: str = Field(
        description="Framework requirement name",
    )
    status: str = Field(
        description="Status: implemented/partial/missing",
    )
    gap_description: str = Field(
        description="Description of any gap",
    )
    confidence: float = Field(
        description="Mapping confidence 0-1",
    )


class RemediationPlanOutput(BaseModel):
    """LLM output for remediation planning."""

    action_items: list[str] = Field(
        description="Specific remediation actions",
    )
    timeline: str = Field(
        description="Estimated timeline",
    )
    estimated_cost: str = Field(
        description="Estimated cost range",
    )
    priority: str = Field(
        description="Priority: critical/high/medium/low",
    )
    owner_role: str = Field(
        description="Recommended owner role",
    )


class ComplianceReportOutput(BaseModel):
    """LLM output for the compliance report."""

    executive_summary: str = Field(
        description="Executive summary of compliance",
    )
    framework_summaries: list[str] = Field(
        description="Per-framework status summaries",
    )
    critical_gaps: list[str] = Field(
        description="Most critical compliance gaps",
    )
    recommendations: list[str] = Field(
        description="Prioritized recommendations",
    )


SYSTEM_MAP_FRAMEWORKS = (
    "You are a compliance analyst mapping security "
    "controls to regulatory framework requirements.\n"
    "For each control:\n"
    "1. Identify the matching framework requirement\n"
    "2. Assess implementation status\n"
    "3. Describe any gaps\n"
    "4. Rate mapping confidence"
)

SYSTEM_REMEDIATION = (
    "You are a compliance remediation planner creating "
    "action plans for compliance gaps.\n"
    "For each gap:\n"
    "1. Define specific remediation actions\n"
    "2. Estimate timeline and cost\n"
    "3. Assign priority\n"
    "4. Recommend an owner role"
)

SYSTEM_REPORT = (
    "You are a compliance officer writing an executive "
    "compliance status report.\n"
    "Produce a summary covering:\n"
    "1. Overall compliance posture\n"
    "2. Per-framework coverage percentages\n"
    "3. Critical gaps requiring immediate action\n"
    "4. Remediation roadmap with milestones"
)
