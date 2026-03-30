"""LLM prompt templates and response schemas for the
Security Orchestration Hub Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class SeverityClassificationOutput(BaseModel):
    """Structured output for severity classification."""

    severity: str = Field(
        description="Classified severity: critical/high/medium/low",
    )
    confidence: float = Field(
        description="Classification confidence 0-1",
    )
    indicators: list[str] = Field(
        description="Key indicators driving classification",
    )
    escalation_required: bool = Field(
        description="Whether escalation is needed",
    )


class PlaybookRoutingOutput(BaseModel):
    """Structured output for playbook routing."""

    playbook_category: str = Field(
        description="Playbook category to route to",
    )
    steps: list[str] = Field(
        description="Ordered execution steps",
    )
    auto_approved: bool = Field(
        description="Whether auto-approval applies",
    )
    rationale: str = Field(
        description="Routing decision rationale",
    )


class OutcomeValidationOutput(BaseModel):
    """Structured output for outcome validation."""

    validated: bool = Field(
        description="Whether outcome meets success criteria",
    )
    success_rate: float = Field(
        description="Success rate 0-1",
    )
    rollback_needed: bool = Field(
        description="Whether rollback is recommended",
    )
    summary: str = Field(
        description="Validation summary for analysts",
    )


class OrchestrationReportOutput(BaseModel):
    """Structured output for final orchestration report."""

    executive_summary: str = Field(
        description="Executive summary of orchestration",
    )
    actions_taken: list[str] = Field(
        description="Actions executed during orchestration",
    )
    recommendations: list[str] = Field(
        description="Follow-up recommendations",
    )
    effectiveness_rating: str = Field(
        description="Effectiveness: high/medium/low",
    )


# --- System prompts ---


SYSTEM_CLASSIFY = """\
You are an expert security event classifier for a \
security orchestration hub.

Given a raw security event with source metadata:
1. Classify severity based on threat indicators, \
blast radius, and asset criticality
2. Identify key indicators driving the classification
3. Determine whether human escalation is required
4. Assess confidence in the classification

Err on the side of caution for production-impacting \
events."""


SYSTEM_ROUTE = """\
You are an expert playbook router for a security \
orchestration hub.

Given a classified security event and its severity:
1. Select the most appropriate playbook category
2. Define ordered execution steps for the playbook
3. Determine whether auto-approval applies based on \
severity and blast radius
4. Provide clear rationale for the routing decision

Prefer containment speed over completeness for \
critical events."""


SYSTEM_VALIDATE = """\
You are an expert outcome validator for a security \
orchestration hub.

Given the executed actions and their results:
1. Validate whether the orchestration achieved its \
objective
2. Calculate the success rate across all actions
3. Determine whether rollback is needed for failures
4. Provide a clear summary for analyst review

Be strict about success criteria for critical events."""


SYSTEM_REPORT = """\
You are an expert security operations reporter \
synthesizing orchestration results.

Given the full orchestration lifecycle (event, \
classification, playbook, actions, validation):
1. Produce an executive summary for SOC leadership
2. List all actions taken with their outcomes
3. Provide actionable recommendations for follow-up
4. Rate overall orchestration effectiveness

Write clearly for both technical and executive \
audiences."""
