"""LLM prompt templates and response schemas for the Chaos Engineering Agent."""

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class ExperimentAnalysisResult(BaseModel):
    """Structured output from LLM experiment analysis."""

    hypothesis_validated: bool = Field(
        description="Whether the experiment hypothesis was validated"
    )
    resilience_score: float = Field(
        ge=0.0, le=1.0, description="Overall resilience score from 0.0 to 1.0"
    )
    key_findings: list[str] = Field(description="Key findings from the experiment observations")
    recommendations: list[str] = Field(
        description="Actionable recommendations to improve resilience"
    )
    summary: str = Field(description="Brief summary of the experiment results")


class ExperimentReportResult(BaseModel):
    """Structured output for the final experiment report."""

    title: str = Field(description="Report title")
    executive_summary: str = Field(
        description="1-2 sentence executive summary of the experiment outcome"
    )
    risk_assessment: str = Field(description="Risk assessment: low, medium, high, critical")
    follow_up_experiments: list[str] = Field(
        description="Suggested follow-up experiments to run next"
    )


# --- Prompt templates ---

SYSTEM_ANALYZE_RESULTS = """\
You are an expert chaos engineer analyzing the results of a \
controlled fault injection experiment.

You are given:
- The experiment definition (fault type, target, hypothesis)
- Safety check results
- Impact observations (baseline vs. during-fault metrics)
- Whether an SLO breach and auto-rollback occurred

Your task is to:
1. Determine whether the experiment hypothesis was validated
2. Assign a resilience score (0.0 = completely failed, 1.0 = fully resilient)
3. Identify key findings from the metric deviations
4. Provide actionable recommendations to improve service resilience

Be specific about which metrics degraded and by how much. \
Focus on what the team should fix before the next experiment."""

SYSTEM_GENERATE_REPORT = """\
You are an expert chaos engineer generating a summary report \
for a completed fault injection experiment.

You are given the full experiment context including the analysis results.

Your task is to:
1. Write a concise title for the report
2. Provide an executive summary (1-2 sentences)
3. Assess the risk level based on experiment findings
4. Suggest follow-up experiments that would further test the service's resilience

Keep the report actionable and concise. Target an engineering audience."""
