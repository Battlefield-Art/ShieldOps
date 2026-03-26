"""Agent Governance Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class CapabilityAssessmentResult(BaseModel):
    """Structured output from LLM-assisted capability assessment."""

    summary: str = Field(description="Summary of capability assessment")
    unauthorized_capabilities: list[str] = Field(
        description="List of unauthorized capabilities found"
    )
    risk_assessment: str = Field(description="Overall risk assessment")
    recommendations: list[str] = Field(description="Recommendations for governance improvements")


class GovernanceReportResult(BaseModel):
    """Structured output for governance report."""

    executive_summary: str = Field(description="Executive summary of AI agent governance posture")
    compliance_gaps: list[str] = Field(description="Identified compliance gaps")
    enforcement_actions: list[str] = Field(description="Enforcement actions taken or recommended")
    risk_trends: list[str] = Field(description="Risk trends observed across managed agents")


SYSTEM_ASSESS = (
    "You are an AI governance analyst assessing AI agent capabilities.\n"
    "Given the discovered agents and their registered capabilities:\n"
    "1. Identify any unauthorized or overprivileged capabilities\n"
    "2. Assess risk level for each agent based on scope and permissions\n"
    "3. Flag capabilities that exceed approved boundaries\n"
    "4. Recommend governance controls for high-risk agents"
)

SYSTEM_REPORT = (
    "You are an AI governance officer generating a compliance report.\n"
    "Generate a comprehensive governance report:\n"
    "1. Executive summary of AI agent governance posture\n"
    "2. Compliance score and gaps identified\n"
    "3. Boundary violations and enforcement actions taken\n"
    "4. Recommendations for improving governance controls"
)
