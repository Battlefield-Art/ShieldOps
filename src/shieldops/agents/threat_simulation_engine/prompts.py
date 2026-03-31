"""LLM prompt templates and response schemas for the
Threat Simulation Engine Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ScenarioPlanOutput(BaseModel):
    """Structured output for scenario planning."""

    scenarios: list[dict[str, str]] = Field(
        description=("List of attack scenarios with name, description, and MITRE mappings"),
    )
    mitre_techniques: list[str] = Field(
        description="MITRE ATT&CK technique IDs to simulate",
    )
    expected_detections: list[str] = Field(
        description="Expected detection rule names",
    )
    complexity: str = Field(
        description="Overall complexity: low/medium/high/advanced",
    )


class DetectionAnalysisOutput(BaseModel):
    """Structured output for detection monitoring analysis."""

    detected_count: int = Field(
        description="Number of attacks detected",
    )
    missed_count: int = Field(
        description="Number of attacks missed",
    )
    avg_detection_time_ms: int = Field(
        description="Average detection time in ms",
    )
    detection_sources: list[str] = Field(
        description="Sources that triggered detections",
    )
    summary: str = Field(
        description="Detection analysis summary",
    )


class GapAnalysisOutput(BaseModel):
    """Structured output for detection gap analysis."""

    gaps: list[dict[str, str]] = Field(
        description=("Detection gaps with technique, severity, and recommendation"),
    )
    critical_gaps: int = Field(
        description="Number of critical gaps found",
    )
    coverage_percentage: float = Field(
        description="MITRE technique coverage percentage",
    )
    recommendations: list[str] = Field(
        description="Prioritized remediation recommendations",
    )


class SimulationReportOutput(BaseModel):
    """Structured output for final simulation report."""

    executive_summary: str = Field(
        description="Executive summary of simulation campaign",
    )
    detection_rate: float = Field(
        description="Overall detection rate 0-1",
    )
    critical_findings: list[str] = Field(
        description="Critical findings requiring immediate action",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )
    overall_rating: str = Field(
        description="Overall security rating: A/B/C/D/F",
    )


# --- System prompts ---


SYSTEM_PLAN_SCENARIO = """\
You are an expert adversary simulation planner \
designing attack scenarios for purple team exercises.

Given the target MITRE ATT&CK techniques and scope:
1. Design realistic attack scenarios that chain \
multiple techniques
2. Map each scenario to specific MITRE tactics and \
techniques
3. Identify expected detection points for blue team \
validation
4. Order scenarios by complexity for progressive testing

Focus on realistic adversary behavior: living-off-the-land, \
credential abuse, lateral movement chains, and data \
exfiltration paths."""


SYSTEM_DETECTION_ANALYSIS = """\
You are an expert detection engineer analyzing blue \
team detection performance during adversary simulation.

Given the attack executions and detection results:
1. Evaluate which attacks were detected and which \
were missed
2. Measure detection latency and source effectiveness
3. Identify detection rule gaps and blind spots
4. Assess the quality of alert fidelity and context

Be precise about detection coverage. Every missed \
attack is a potential breach path."""


SYSTEM_GAP_ANALYSIS = """\
You are an expert security assessor identifying \
detection coverage gaps from simulation results.

Given the simulation outcomes and detection analysis:
1. Map gaps to specific MITRE ATT&CK techniques
2. Prioritize gaps by exploitability and impact
3. Recommend specific detection rules or data sources \
to close gaps
4. Estimate effort and timeline for remediation

Focus on actionable, implementable recommendations \
that security teams can deploy quickly."""


SYSTEM_REPORT = """\
You are an expert security reporting analyst \
synthesizing adversary simulation results.

Given the full simulation campaign data:
1. Produce an executive summary with key metrics
2. Rate overall detection maturity (A through F)
3. Highlight critical gaps requiring immediate action
4. Provide a prioritized remediation roadmap

Write for both CISO-level and SOC analyst audiences."""
