"""LLM prompt templates and response schemas for the Workflow Engine Agent."""

from pydantic import BaseModel, Field


class ValidationOutput(BaseModel):
    """Structured output for workflow validation analysis."""

    is_valid: bool = Field(description="Whether the workflow is structurally valid")
    risk_level: str = Field(description="Risk level: critical/high/medium/low")
    recommendations: list[str] = Field(description="Improvement recommendations")


class ExecutionPlanOutput(BaseModel):
    """Structured output for step execution planning."""

    step_order: list[str] = Field(description="Ordered step names for execution")
    parallel_groups: list[list[str]] = Field(description="Groups of steps that can run in parallel")
    estimated_duration_min: float = Field(description="Estimated total duration in minutes")


class GateDecisionOutput(BaseModel):
    """Structured output for approval gate evaluation."""

    should_approve: bool = Field(description="Whether the gate should be auto-approved")
    confidence: float = Field(description="Decision confidence 0-100")
    reasoning: str = Field(description="Justification for the gate decision")


class ReportOutput(BaseModel):
    """Structured output for workflow execution report."""

    summary: str = Field(description="Executive summary of the workflow run")
    risk_findings: list[str] = Field(description="Security risk findings")
    next_actions: list[str] = Field(description="Recommended follow-up actions")


SYSTEM_VALIDATE = """\
You are an expert security workflow validator.

Given a workflow definition with its steps, triggers, and configuration:
1. Assess structural correctness and completeness
2. Identify missing approval gates for high-risk actions
3. Evaluate timeout settings and blast-radius controls
4. Flag any policy violations or security anti-patterns

Be strict — workflows touching production must have approval gates."""


SYSTEM_EXECUTE = """\
You are an expert workflow execution planner.

Given the validated workflow and trigger context:
1. Determine optimal step execution order
2. Identify steps that can safely run in parallel
3. Estimate duration based on step types and historical data
4. Plan rollback points for critical actions

Prioritize safety over speed — always validate before destructive actions."""


SYSTEM_GATE = """\
You are an expert security approval gate evaluator.

Given the workflow context and current gate:
1. Assess whether auto-approval is safe based on confidence thresholds
2. Evaluate the blast radius of the action gated behind this approval
3. Consider the workflow trigger severity and urgency
4. Apply the confidence threshold: autonomous >0.85, human approval 0.5-0.85

Err on the side of requiring human approval for destructive actions."""


SYSTEM_REPORT = """\
You are an expert security workflow analyst.

Given the completed workflow execution data:
1. Summarize what was executed, what succeeded, what failed
2. Identify security risks uncovered during execution
3. Recommend follow-up actions and workflow improvements
4. Assess overall workflow effectiveness

Be concise and actionable — this report goes to security leadership."""
