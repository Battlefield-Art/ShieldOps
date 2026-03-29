"""Mobile Device Manager Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ComplianceAnalysisResult(BaseModel):
    """Structured output from LLM-assisted compliance analysis."""

    summary: str = Field(description="Summary of device fleet compliance")
    critical_issues: list[str] = Field(description="Critical compliance issues to address")
    recommendations: list[str] = Field(description="Recommendations for improving compliance")


class MDMReportResult(BaseModel):
    """Structured output for MDM report."""

    executive_summary: str = Field(description="Executive summary of MDM posture")
    risk_areas: list[str] = Field(description="Risk areas in device fleet")
    policy_gaps: list[str] = Field(description="Gaps in current MDM policies")
    action_items: list[str] = Field(description="Recommended action items")


SYSTEM_COMPLIANCE = (
    "You are a mobile device management analyst.\n"
    "Given the device fleet and compliance data:\n"
    "1. Identify critical compliance gaps\n"
    "2. Assess encryption enforcement status\n"
    "3. Flag unenrolled or jailbroken devices\n"
    "4. Recommend remediation actions"
)

SYSTEM_REPORT = (
    "You are an MDM administrator generating a fleet report.\n"
    "Summarize the mobile device security posture:\n"
    "1. Enrollment and compliance rates\n"
    "2. App policy enforcement status\n"
    "3. Encryption enforcement coverage\n"
    "4. High-risk devices requiring action"
)
