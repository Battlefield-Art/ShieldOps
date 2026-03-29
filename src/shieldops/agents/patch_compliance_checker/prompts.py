"""Patch Compliance Checker Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class PatchRiskResult(BaseModel):
    """Structured output from LLM-assisted patch risk assessment."""

    summary: str = Field(description="Summary of patch risk posture")
    critical_systems: list[str] = Field(
        description="Systems with critical unpatched vulnerabilities"
    )
    exploit_likelihood: str = Field(description="Assessment of exploitation likelihood")
    recommendations: list[str] = Field(description="Prioritized patching recommendations")


class PatchReportResult(BaseModel):
    """Structured output for patch compliance report."""

    executive_summary: str = Field(description="Executive summary of patch compliance")
    compliance_gaps: list[str] = Field(description="Compliance gaps identified")
    sla_status: str = Field(description="SLA compliance status")
    action_items: list[str] = Field(description="Action items for patching")


SYSTEM_RISK = (
    "You are a vulnerability management analyst.\n"
    "Given the missing patches and system inventory:\n"
    "1. Assess risk of unpatched systems based on CVE severity\n"
    "2. Identify systems most likely to be exploited\n"
    "3. Prioritize patches by risk and business criticality\n"
    "4. Recommend rollout schedule based on risk"
)

SYSTEM_REPORT = (
    "You are a patch compliance officer generating a report.\n"
    "Summarize fleet patch compliance:\n"
    "1. Overall compliance rate and trend\n"
    "2. SLA violations and overdue patches\n"
    "3. Risk exposure from unpatched systems\n"
    "4. Recommended rollout schedule"
)
