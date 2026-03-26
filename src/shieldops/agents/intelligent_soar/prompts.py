"""LLM prompt templates and response schemas for Intelligent SOAR."""

from pydantic import BaseModel, Field


class TriggerAnalysisOutput(BaseModel):
    """Structured output for trigger analysis."""

    alert_type: str = Field(
        description="Classified alert type",
    )
    severity: str = Field(
        description="Severity: critical/high/medium/low",
    )
    indicators: list[str] = Field(
        description="Extracted indicators of compromise",
    )
    confidence: float = Field(
        description="Classification confidence 0-100",
    )


class PlaybookSelectionOutput(BaseModel):
    """Structured output for playbook selection."""

    playbook_id: str = Field(
        description="Selected playbook identifier",
    )
    playbook_type: str = Field(
        description="Playbook type category",
    )
    match_score: float = Field(
        description="Match confidence 0-100",
    )
    reasoning: str = Field(
        description="Why this playbook was selected",
    )
    requires_approval: bool = Field(
        description="Whether human approval is needed",
    )


class AdaptationOutput(BaseModel):
    """Structured output for dynamic adaptation."""

    should_adapt: bool = Field(
        description="Whether adaptation is needed",
    )
    adapted_action: str = Field(
        description="New action to take",
    )
    reasoning: str = Field(
        description="Adaptation reasoning",
    )
    confidence: float = Field(
        description="Confidence in adaptation 0-100",
    )


class OutcomeAssessmentOutput(BaseModel):
    """Structured output for outcome validation."""

    threat_neutralized: bool = Field(
        description="Whether the threat is neutralized",
    )
    residual_risk: float = Field(
        description="Remaining risk score 0-1",
    )
    recommendations: list[str] = Field(
        description="Follow-up recommendations",
    )
    effectiveness_score: float = Field(
        description="Playbook effectiveness 0-100",
    )


SYSTEM_TRIGGER_ANALYSIS = """\
You are an expert security alert triage analyst \
for an AI-driven SOAR platform.

Given the incoming trigger data:
1. Classify the alert type and severity
2. Extract all indicators of compromise (IOCs)
3. Assess urgency and blast radius
4. Determine if this is a true positive

Prioritize speed and accuracy of classification."""


SYSTEM_PLAYBOOK_SELECTION = """\
You are an intelligent SOAR playbook selector. \
Unlike legacy XSOAR drag-and-drop playbooks, you \
select LangGraph-native composable playbooks.

Given the trigger analysis:
1. Match to the best response playbook type
2. Consider playbook effectiveness history
3. Assess if automatic execution is safe
4. Determine if human approval is required

Playbook types: investigation, containment, \
eradication, recovery, compliance.

Balance automation speed with safety."""


SYSTEM_ADAPT_EXECUTION = """\
You are a dynamic SOAR execution adapter. You \
analyze intermediate findings during playbook \
execution and decide whether to modify the \
remaining steps.

Given execution results so far:
1. Assess if findings change the threat picture
2. Decide whether to add, skip, or modify steps
3. Explain your adaptation reasoning
4. Rate confidence in the adaptation

This is the key differentiator vs rigid XSOAR \
playbooks — adapt in real-time."""


SYSTEM_VALIDATE_OUTCOME = """\
You are an expert outcome validator for SOAR \
playbook executions.

Given the completed playbook execution:
1. Verify the threat has been neutralized
2. Calculate residual risk score
3. Identify any gaps in the response
4. Recommend follow-up actions

Be thorough — missed threats compound."""
