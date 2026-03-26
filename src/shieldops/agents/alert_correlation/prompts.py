"""LLM prompt templates and response schemas for the Alert Correlation Agent."""

from pydantic import BaseModel, Field


class CorrelationAnalysisOutput(BaseModel):
    """Structured output for LLM-driven correlation analysis."""

    root_cause_hypothesis: str = Field(
        description="Hypothesis for the root cause linking correlated alerts"
    )
    confidence: float = Field(description="Confidence in the correlation 0-1")
    kill_chain_stage: str = Field(
        description="Kill chain stage: Reconnaissance/Exploitation/Lateral Movement/etc."
    )
    reasoning: str = Field(description="Step-by-step correlation reasoning")


class IncidentPrioritizationOutput(BaseModel):
    """Structured output for LLM-driven incident prioritization."""

    priority: str = Field(description="Priority level: P1/P2/P3/P4/P5")
    title: str = Field(description="Concise incident title")
    narrative: str = Field(description="Human-readable narrative of the incident")
    recommended_action: str = Field(description="Recommended next action for responders")
    auto_actionable: bool = Field(description="Whether this can be auto-remediated")
    estimated_impact: str = Field(description="Estimated blast radius / business impact")


class CorrelationReportOutput(BaseModel):
    """Structured output for the final correlation report."""

    executive_summary: str = Field(description="High-level summary for leadership")
    noise_reduction_pct: float = Field(description="Percentage of alerts reduced via correlation")
    top_incidents: list[str] = Field(description="Top incident titles requiring attention")
    recommendations: list[str] = Field(description="Actionable recommendations")


SYSTEM_CORRELATE = """\
You are an expert security analyst performing multi-source alert correlation.

Given a set of normalized alerts, identify correlation clusters based on:
1. Temporal proximity — alerts occurring within a short time window
2. Causal relationships — alerts that share root causes or attack patterns
3. Identity overlap — alerts referencing the same entities (IPs, users, hosts)
4. Kill chain progression — alerts mapping to sequential attack stages

For each cluster, provide:
- A root cause hypothesis explaining why these alerts are related
- Kill chain stage classification
- Confidence score (0-1)

Prioritize reducing alert fatigue while preserving detection fidelity."""


SYSTEM_PRIORITIZE = """\
You are an expert incident responder prioritizing correlated alert clusters.

Given a correlation cluster with its alerts, kill chain stage, and confidence:
1. Assign a priority level (P1=critical, P2=high, P3=medium, P4=low, P5=info)
2. Write a concise incident title
3. Build a human-readable narrative of what happened
4. Recommend the next action for the SOC team
5. Determine if this can be auto-remediated safely

Consider: severity of constituent alerts, kill chain progression, affected asset \
criticality, and confidence in the correlation."""


SYSTEM_REPORT = """\
You are a security operations leader summarizing alert correlation results.

Given the correlation run results (raw alert count, cluster count, incidents):
1. Write an executive summary suitable for CISO/VP-level audience
2. Calculate the noise reduction percentage
3. Highlight the top incidents requiring immediate attention
4. Provide actionable recommendations

Focus on signal-to-noise improvement and time-to-respond reduction."""
