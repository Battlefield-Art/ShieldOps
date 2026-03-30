"""Database Security Scanner Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ConfigInsight(BaseModel):
    """Structured output from configuration scan."""

    summary: str = Field(
        description="Brief config security overview",
    )
    critical_issues: list[str] = Field(
        description="Critical misconfigurations found",
    )
    quick_fixes: list[str] = Field(
        description="Quick remediation actions",
    )


class AuthInsight(BaseModel):
    """Structured output from auth weakness check."""

    summary: str = Field(
        description="Authentication security overview",
    )
    weak_points: list[str] = Field(
        description="Identified authentication weaknesses",
    )
    hardening_steps: list[str] = Field(
        description="Steps to harden authentication",
    )


class ExposureInsight(BaseModel):
    """Structured output from data exposure detection."""

    summary: str = Field(
        description="Data exposure overview",
    )
    sensitive_fields: list[str] = Field(
        description="Fields with sensitive data exposure",
    )
    protection_actions: list[str] = Field(
        description="Data protection recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of database security",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_CONFIG_SCAN = (
    "You are a database security analyst reviewing "
    "configuration findings.\n"
    "1. Identify critical misconfigurations\n"
    "2. Flag unencrypted connections and storage\n"
    "3. Check for exposed ports and public access\n"
    "4. Recommend remediation priorities"
)

SYSTEM_AUTH_CHECK = (
    "You are a database authentication specialist "
    "reviewing auth weaknesses.\n"
    "1. Identify weak or default credentials\n"
    "2. Check for missing MFA or cert-based auth\n"
    "3. Detect overly permissive auth policies\n"
    "4. Recommend auth hardening steps"
)

SYSTEM_REPORT = (
    "You are a database security advisor generating "
    "an executive security assessment.\n"
    "1. Summarize findings by severity\n"
    "2. Highlight critical and high-risk items\n"
    "3. Quantify exposure and risk surface\n"
    "4. Recommend prioritized remediation plan"
)
