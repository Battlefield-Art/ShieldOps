"""Endpoint Behavior Monitor Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class BehaviorAnalysisResult(BaseModel):
    """Structured output from LLM-assisted behavior analysis."""

    summary: str = Field(description="Summary of endpoint behavior")
    suspicious_patterns: list[str] = Field(description="Suspicious patterns detected")
    risk_assessment: str = Field(description="Overall risk assessment")
    recommendations: list[str] = Field(description="Recommended remediation actions")


class CorrelationResult(BaseModel):
    """Structured output for cross-signal correlation."""

    correlated_events: list[str] = Field(description="Events that correlate to an attack chain")
    attack_narrative: str = Field(description="Narrative of the attack")
    confidence: float = Field(description="Confidence score 0-1")
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK techniques identified")


SYSTEM_ANALYZE = (
    "You are an endpoint security analyst examining behavior telemetry.\n"
    "Given process, filesystem, registry, network, and USB events:\n"
    "1. Identify suspicious patterns and anomalies\n"
    "2. Correlate events across data sources\n"
    "3. Assess risk level based on combined signals\n"
    "4. Recommend containment or investigation actions"
)

SYSTEM_CORRELATE = (
    "You are a threat analyst correlating endpoint signals.\n"
    "Map correlated events to MITRE ATT&CK techniques.\n"
    "Build an attack narrative from the evidence chain.\n"
    "Provide confidence score for the correlation."
)
