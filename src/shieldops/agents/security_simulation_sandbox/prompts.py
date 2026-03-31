"""LLM prompt templates and response schemas for the
Security Simulation Sandbox Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ScenarioConfigOutput(BaseModel):
    """Structured output for scenario configuration."""

    scenarios: list[dict[str, str]] = Field(
        description="Configured test scenarios with attack vectors",
    )
    mitre_techniques: list[str] = Field(
        description="MITRE ATT&CK technique IDs covered",
    )
    risk_assessment: str = Field(
        description="Risk assessment of the test plan",
    )
    confidence: float = Field(
        description="Confidence in scenario coverage 0-1",
    )


class TestAnalysisOutput(BaseModel):
    """Structured output for test result analysis."""

    detection_gaps: list[str] = Field(
        description="Gaps in detection coverage",
    )
    evasion_techniques: list[str] = Field(
        description="Techniques that evaded detection",
    )
    risk_score: float = Field(
        description="Aggregate risk score 0-10",
    )
    summary: str = Field(
        description="Analysis summary for security team",
    )


class SandboxReportOutput(BaseModel):
    """Structured output for final sandbox report."""

    executive_summary: str = Field(
        description="Executive summary of sandbox testing",
    )
    detection_effectiveness: float = Field(
        description="Overall detection rate 0-1",
    )
    recommendations: list[str] = Field(
        description="Actionable remediation recommendations",
    )
    mitre_coverage: list[str] = Field(
        description="MITRE techniques tested",
    )
    risk_rating: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_SCENARIO = """\
You are an expert security testing architect configuring \
sandbox test scenarios.

Given the target environment and testing objectives:
1. Design attack scenarios covering key MITRE ATT&CK \
techniques
2. Configure payload parameters for realistic simulation
3. Define expected detection outcomes for each scenario
4. Prioritize scenarios by risk and detection gap coverage

Focus on realistic attack chains that test defense \
effectiveness against APTs, ransomware, and insider \
threats."""


SYSTEM_ANALYSIS = """\
You are an expert security analyst reviewing sandbox \
test results.

Given the test execution results from isolated sandboxes:
1. Identify detection gaps where attacks went undetected
2. Calculate detection coverage across MITRE ATT&CK matrix
3. Assess mean time to detect for each attack category
4. Recommend control improvements for identified gaps

Be precise about coverage percentages and detection \
latency metrics."""


SYSTEM_REPORT = """\
You are an expert security testing reporter synthesizing \
sandbox campaign results.

Given the full test campaign (scenarios, results, analysis):
1. Produce an executive summary for security leadership
2. List remediation recommendations prioritized by risk
3. Summarize MITRE ATT&CK coverage achieved vs gaps
4. Rate overall defensive posture effectiveness

Write clearly for both technical and executive audiences."""
