"""Certificate Manager Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ExpiryAnalysisResult(BaseModel):
    """Structured output from LLM-assisted expiry analysis."""

    summary: str = Field(description="Summary of certificate expiry status")
    critical_certs: list[str] = Field(
        description="Certificates requiring immediate attention"
    )
    risk_assessment: str = Field(
        description="Overall risk assessment of certificate posture"
    )
    recommendations: list[str] = Field(
        description="Prioritized recommendations for certificate management"
    )


class RotationPlanResult(BaseModel):
    """Structured output for rotation planning."""

    summary: str = Field(description="Summary of rotation plan")
    rotation_order: list[str] = Field(
        description="Recommended order for certificate rotations"
    )
    risks: list[str] = Field(
        description="Risks associated with the rotation plan"
    )
    rollback_steps: list[str] = Field(
        description="Steps to rollback if rotation fails"
    )


class CertReportResult(BaseModel):
    """Structured output for certificate management report."""

    executive_summary: str = Field(description="Executive summary")
    compliance_status: str = Field(
        description="Compliance status of certificate inventory"
    )
    action_items: list[str] = Field(
        description="Action items for the security team"
    )
    improvements: list[str] = Field(
        description="Suggested improvements to certificate management"
    )


SYSTEM_EXPIRY_ANALYSIS = (
    "You are a PKI expert analyzing TLS certificate expiry status.\n"
    "For the certificate inventory:\n"
    "1. Identify certificates at critical risk of expiry\n"
    "2. Assess overall risk posture of the certificate landscape\n"
    "3. Prioritize which certificates need immediate renewal\n"
    "4. Recommend improvements to prevent future expiry incidents"
)

SYSTEM_ROTATION_PLAN = (
    "You are a PKI automation engineer planning certificate rotations.\n"
    "For certificates requiring rotation:\n"
    "1. Determine the optimal rotation order to minimize service disruption\n"
    "2. Identify dependencies between certificates\n"
    "3. Assess risks of each rotation and plan mitigations\n"
    "4. Define rollback procedures for each rotation step"
)

SYSTEM_REPORT = (
    "You are a security compliance officer reviewing certificate management.\n"
    "Generate a comprehensive report:\n"
    "1. Executive summary of certificate inventory health\n"
    "2. Compliance status against security standards (PCI-DSS, SOC 2)\n"
    "3. Action items ranked by priority\n"
    "4. Strategic improvements for certificate lifecycle management"
)
