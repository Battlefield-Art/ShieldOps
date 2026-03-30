"""Secret Rotation Manager Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class RotationRiskInsight(BaseModel):
    """Structured output from rotation risk assessment."""

    summary: str = Field(
        description="Brief risk assessment overview",
    )
    critical_secrets: list[str] = Field(
        description="Secrets requiring immediate rotation",
    )
    risk_factors: list[str] = Field(
        description="Key risk factors identified",
    )


class RotationPlanInsight(BaseModel):
    """Structured output from rotation planning."""

    summary: str = Field(
        description="Rotation plan overview",
    )
    zero_downtime_strategies: list[str] = Field(
        description="Strategies to ensure zero downtime",
    )
    precautions: list[str] = Field(
        description="Precautions for safe rotation",
    )


class HealthInsight(BaseModel):
    """Structured output from health verification."""

    summary: str = Field(
        description="Post-rotation health overview",
    )
    healthy_services: list[str] = Field(
        description="Services confirmed healthy",
    )
    concerns: list[str] = Field(
        description="Any health concerns detected",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of rotation cycle",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ASSESS = (
    "You are a secrets management security analyst "
    "assessing credential rotation risk.\n"
    "1. Evaluate secret age against rotation policies\n"
    "2. Identify high-risk secrets (exposed, stale, "
    "over-permissioned)\n"
    "3. Score blast radius based on consumer count\n"
    "4. Prioritize rotation by risk and compliance"
)

SYSTEM_PLAN = (
    "You are a secrets rotation engineer planning "
    "zero-downtime credential rotation.\n"
    "1. Select dual-write or blue-green strategy\n"
    "2. Identify pre-rotation health checks\n"
    "3. Define rollback procedures\n"
    "4. Minimize consumer disruption"
)

SYSTEM_REPORT = (
    "You are a security operations advisor generating "
    "a secret rotation cycle report.\n"
    "1. Summarize rotations completed and failed\n"
    "2. Highlight secrets still needing attention\n"
    "3. Quantify risk reduction achieved\n"
    "4. Recommend policy and schedule improvements"
)
