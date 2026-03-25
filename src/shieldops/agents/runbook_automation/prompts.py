"""LLM prompt templates and response schemas for the Runbook Automation Agent."""

from pydantic import BaseModel, Field


class RunbookSelectionOutput(BaseModel):
    """Structured output for runbook selection reasoning."""

    selected_runbook: str = Field(description="Name of the selected runbook")
    rationale: str = Field(description="Why this runbook was chosen")
    risk_assessment: str = Field(description="Risk assessment for this execution")


class ExecutionPlanOutput(BaseModel):
    """Structured output for execution planning."""

    strategy: str = Field(description="Execution strategy (sequential/parallel)")
    estimated_risk: float = Field(description="Estimated risk score 0-100")
    reasoning: str = Field(description="Planning reasoning")


class OutcomeAnalysisOutput(BaseModel):
    """Structured output for outcome verification analysis."""

    overall_success: bool = Field(description="Whether the runbook succeeded")
    confidence: float = Field(description="Confidence in outcome assessment 0-1")
    summary: str = Field(description="Human-readable outcome summary")


SYSTEM_SELECT = """\
You are an expert SRE runbook selector.

Given the incident context and available runbooks:
1. Select the most appropriate runbook for the situation
2. Assess the risk of executing it against the target service
3. Explain your rationale

Consider: blast radius, service criticality, time of day, recent changes."""


SYSTEM_EXECUTE = """\
You are an expert automated runbook executor.

Given the runbook steps and precondition results:
1. Plan the optimal execution strategy
2. Identify steps that could be parallelized safely
3. Estimate risk for the overall execution

Minimize blast radius and ensure all changes are auditable."""


SYSTEM_VERIFY = """\
You are an expert SRE outcome verifier.

Given the execution results and verification checks:
1. Determine whether the runbook achieved its intended outcome
2. Identify any partial failures or degraded states
3. Recommend follow-up actions if needed

Be conservative — flag any uncertainty for human review."""
