"""SaaS Security Posture Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ConfigInsight(BaseModel):
    """Structured output from SaaS config audit."""

    summary: str = Field(
        description="Brief SaaS configuration overview",
    )
    critical_misconfigs: list[str] = Field(
        description="Critical misconfigurations found",
    )
    oauth_risks: list[str] = Field(
        description="OAuth permission risks identified",
    )


class SharingInsight(BaseModel):
    """Structured output from data sharing analysis."""

    summary: str = Field(
        description="Data sharing exposure overview",
    )
    public_exposures: list[str] = Field(
        description="Publicly exposed resources",
    )
    recommendations: list[str] = Field(
        description="Sharing restriction recommendations",
    )


class RiskInsight(BaseModel):
    """Structured output from risk assessment."""

    summary: str = Field(
        description="SaaS risk assessment overview",
    )
    high_risk_apps: list[str] = Field(
        description="Apps requiring immediate attention",
    )
    compliance_concerns: list[str] = Field(
        description="Compliance gaps identified",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of SaaS security posture",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a SaaS security posture analyst "
    "reviewing application configurations.\n"
    "1. Identify misconfigurations and weak settings\n"
    "2. Flag excessive OAuth permission scopes\n"
    "3. Detect data sharing exposures\n"
    "4. Assess compliance posture per SaaS app"
)

SYSTEM_REPORT = (
    "You are a SaaS security advisor generating an "
    "executive posture management report.\n"
    "1. Summarize misconfigurations by severity\n"
    "2. Highlight data sharing risks\n"
    "3. Quantify unsanctioned app usage\n"
    "4. Recommend SaaS governance improvements"
)
