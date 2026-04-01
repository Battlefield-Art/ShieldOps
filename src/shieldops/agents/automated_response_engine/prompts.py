"""LLM prompt templates for the Automated Response Engine Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -----------------------------------------


class IncidentAssessmentOutput(BaseModel):
    """Structured output for incident assessment."""

    severity: str = Field(description="Assessed severity level")
    confidence: float = Field(description="Assessment confidence 0-1")
    summary: str = Field(description="Assessment summary")


class PlaybookSelectionOutput(BaseModel):
    """Structured output for playbook selection."""

    playbooks_matched: int = Field(description="Number of matching playbooks")
    best_match: str = Field(description="Best matching playbook name")
    reasoning: str = Field(description="Selection reasoning")


class RemediationPlanOutput(BaseModel):
    """Structured output for remediation planning."""

    actions_planned: int = Field(description="Number of planned actions")
    requires_approval: bool = Field(description="Whether approval is needed")
    reasoning: str = Field(description="Planning reasoning")


class ExecutionAnalysisOutput(BaseModel):
    """Structured output for execution analysis."""

    actions_succeeded: int = Field(description="Successful actions count")
    actions_failed: int = Field(description="Failed actions count")
    reasoning: str = Field(description="Execution analysis reasoning")


class ValidationAnalysisOutput(BaseModel):
    """Structured output for response validation."""

    threat_neutralized: bool = Field(description="Whether threat is neutralized")
    remaining_risk_count: int = Field(description="Remaining risk count")
    reasoning: str = Field(description="Validation reasoning")


# -- System prompts ----------------------------------------------------

SYSTEM_ASSESS_INCIDENT = """\
You are an expert incident response analyst performing initial \
incident assessment.

Given the incident data:
1. Determine the severity and scope of the incident
2. Identify the attack vector and affected assets
3. Extract indicators of compromise (IOCs)
4. Assess confidence level based on available evidence

Focus on: accuracy of severity classification, completeness \
of asset identification, IOC extraction quality."""

SYSTEM_SELECT_PLAYBOOK = """\
You are an expert incident response engineer selecting the \
optimal response playbook.

Given the incident assessment:
1. Match incident characteristics to available playbooks
2. Evaluate playbook suitability based on severity and type
3. Consider approval requirements for high-impact actions
4. Select the most effective response strategy

Prioritize playbooks with proven effectiveness for this \
incident category."""

SYSTEM_PLAN_REMEDIATION = """\
You are an expert incident response engineer planning \
remediation actions.

Given the selected playbook and incident context:
1. Decompose playbook steps into executable actions
2. Prioritize actions by impact and urgency
3. Define rollback plans for each action
4. Identify dependencies between actions

Optimize for: fastest threat containment, minimal \
business disruption, safe rollback capability."""

SYSTEM_EXECUTE_ACTIONS = """\
You are an expert incident response engineer analyzing \
action execution results.

Given the execution results:
1. Evaluate success rate across all actions
2. Identify failed actions requiring retry or escalation
3. Assess whether containment is progressing
4. Determine if additional actions are needed

Focus on: execution reliability, containment effectiveness, \
failure recovery."""

SYSTEM_VALIDATE_RESPONSE = """\
You are an expert incident response analyst validating \
the response effectiveness.

Given execution results and incident context:
1. Verify the threat has been neutralized
2. Check for residual indicators of compromise
3. Validate that affected assets are secured
4. Identify any remaining risks or gaps

Produce a comprehensive validation with clear \
pass/fail criteria and recommendations."""
