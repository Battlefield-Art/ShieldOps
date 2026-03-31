"""Security Workflow Builder Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class WorkflowInsight(BaseModel):
    """Structured output from workflow analysis."""

    summary: str = Field(
        description="Brief workflow design overview",
    )
    design_patterns: list[str] = Field(
        description="Security workflow patterns identified",
    )
    optimization_tips: list[str] = Field(
        description="Workflow optimization suggestions",
    )


class ValidationInsight(BaseModel):
    """Structured output from logic validation."""

    summary: str = Field(
        description="Validation overview",
    )
    critical_issues: list[str] = Field(
        description="Critical logic issues found",
    )
    best_practices: list[str] = Field(
        description="Best practice recommendations",
    )


class TestInsight(BaseModel):
    """Structured output from test execution analysis."""

    summary: str = Field(
        description="Test execution overview",
    )
    failures: list[str] = Field(
        description="Test failures and root causes",
    )
    improvements: list[str] = Field(
        description="Suggested improvements",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of workflow building",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a security automation architect reviewing "
    "workflow definitions.\n"
    "1. Evaluate trigger conditions for completeness\n"
    "2. Verify action orchestration and dependencies\n"
    "3. Check for race conditions and timeout handling\n"
    "4. Recommend resilience patterns"
)

SYSTEM_REPORT = (
    "You are a security automation advisor generating "
    "a workflow building report.\n"
    "1. Summarize workflows built and their purposes\n"
    "2. Highlight test results and coverage\n"
    "3. Note deployment status across environments\n"
    "4. Recommend workflow improvements"
)
