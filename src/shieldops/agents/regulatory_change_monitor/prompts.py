"""LLM prompt templates and response schemas for the
Regulatory Change Monitor Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ChangeParseOutput(BaseModel):
    """Structured output for regulatory change parsing."""

    changes: list[dict[str, str]] = Field(
        description=("Parsed regulatory changes with title, framework, and type"),
    )
    frameworks_affected: list[str] = Field(
        description="Regulatory frameworks affected",
    )
    urgency: str = Field(
        description="Urgency: immediate/near-term/planned",
    )
    summary: str = Field(
        description="Summary of parsed changes",
    )


class ImpactAssessmentOutput(BaseModel):
    """Structured output for impact assessment."""

    impact_level: str = Field(
        description="Impact: critical/high/medium/low/informational",
    )
    affected_controls: list[str] = Field(
        description="Internal controls affected by change",
    )
    compliance_gap: bool = Field(
        description="Whether a compliance gap exists",
    )
    estimated_effort_hours: int = Field(
        description="Estimated remediation effort in hours",
    )
    summary: str = Field(
        description="Impact assessment summary",
    )


class ControlMappingOutput(BaseModel):
    """Structured output for control gap mapping."""

    mappings: list[dict[str, str]] = Field(
        description="Control mappings with control_id, status, and gap",
    )
    gaps_found: int = Field(
        description="Number of control gaps identified",
    )
    remediation_needed: bool = Field(
        description="Whether remediation actions are needed",
    )


class RegulatoryReportOutput(BaseModel):
    """Structured output for final regulatory report."""

    executive_summary: str = Field(
        description="Executive summary for leadership",
    )
    critical_changes: list[str] = Field(
        description="Changes requiring immediate attention",
    )
    action_items: list[dict[str, str]] = Field(
        description="Prioritized action items",
    )
    compliance_posture: str = Field(
        description="Overall compliance posture assessment",
    )


# --- System prompts ---


SYSTEM_PARSE = """\
You are an expert regulatory analyst parsing regulatory \
updates and framework changes.

Given the raw regulatory feed data:
1. Identify specific changes to requirements, controls, \
or guidance
2. Map changes to the correct framework (NIST, ISO, \
GDPR, HIPAA, etc.)
3. Classify change type (new requirement, amendment, \
clarification, sunset)
4. Assess urgency based on effective dates and penalties

Be precise: misclassified changes cause compliance gaps."""


SYSTEM_IMPACT = """\
You are an expert compliance analyst assessing the impact \
of regulatory changes on enterprise operations.

Given the parsed regulatory change and organization context:
1. Identify which internal controls are affected
2. Assess whether current posture meets new requirements
3. Estimate remediation effort in engineering hours
4. Flag compliance gaps that create legal or financial risk

Err on the side of caution: underestimating impact leads \
to audit findings."""


SYSTEM_CONTROLS = """\
You are an expert GRC analyst mapping regulatory \
requirements to internal security controls.

Given the regulatory change and current control catalog:
1. Map new requirements to existing controls
2. Identify gaps where no control covers the requirement
3. Suggest control enhancements or new controls needed
4. Prioritize by risk and compliance deadline

Use standard control frameworks (NIST 800-53, CIS, \
ISO 27001 Annex A) as reference."""


SYSTEM_REPORT = """\
You are an expert regulatory compliance reporter \
synthesizing change monitoring results.

Given the full analysis (changes, impacts, control \
mappings, action items):
1. Produce an executive summary for compliance leadership
2. Highlight changes requiring immediate attention
3. Provide a prioritized action item list
4. Assess overall compliance posture impact

Write for both legal/compliance and technical audiences."""
