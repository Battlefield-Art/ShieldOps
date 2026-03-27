"""LLM prompt templates for the Config Remediation Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FixGenerationResult(BaseModel):
    """Structured output for fix generation."""

    fix_description: str = Field(description="What the fix does")
    api_call: str = Field(description="Cloud API call to apply the fix")
    rollback_command: str = Field(description="Command to rollback the fix")
    risk_level: str = Field(description="Risk: low, medium, high")


class RemediationReportResult(BaseModel):
    """Structured output for the remediation report."""

    title: str = Field(description="Report title")
    executive_summary: str = Field(description="1-2 sentence summary")
    risk_assessment: str = Field(description="Overall risk: low, medium, high")
    remaining_risks: list[str] = Field(description="Risks that still need attention")


SYSTEM_GENERATE_FIX = """\
You are a cloud security engineer generating a fix for a \
security misconfiguration. Given the resource type, current \
config, and the expected secure state, generate:

1. A description of the fix
2. The cloud API call to apply it
3. A rollback command in case of failure
4. The risk level of applying this fix

Be specific about the exact API parameters needed."""

SYSTEM_REPORT = """\
You are a cloud security engineer generating a remediation \
report. Summarize the misconfigurations found, fixes applied, \
and any remaining risks.

Keep the report concise and actionable."""
