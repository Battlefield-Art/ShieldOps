"""Agent Behavioral Firewall — LLM prompt templates."""

from pydantic import BaseModel, Field


class AnomalyAnalysisResult(BaseModel):
    """Structured output from LLM-assisted anomaly analysis."""

    summary: str = Field(description="Brief summary of anomaly analysis findings")
    anomaly_count: int = Field(description="Number of confirmed anomalies")
    risk_level: str = Field(description="Overall risk level: low, medium, high, critical")
    anomaly_details: list[str] = Field(description="Detailed description of each confirmed anomaly")
    recommended_actions: list[str] = Field(
        description="Recommended actions to mitigate detected anomalies"
    )


class PolicyRecommendationResult(BaseModel):
    """Structured output from LLM-assisted policy recommendation."""

    summary: str = Field(description="Brief summary of recommended policy changes")
    new_rules: list[str] = Field(description="New policy rules to add")
    tightened_rules: list[str] = Field(description="Existing rules to tighten")
    confidence: float = Field(description="Confidence in recommendations 0.0-1.0")


class ThreatAssessmentResult(BaseModel):
    """Structured output from LLM-assisted threat assessment."""

    summary: str = Field(description="Brief threat assessment summary")
    threat_level: str = Field(description="Threat level: none, low, medium, high, critical")
    attack_patterns: list[str] = Field(description="Identified attack patterns if any")
    immediate_actions: list[str] = Field(description="Actions to take immediately")
    kill_switch_recommended: bool = Field(
        description="Whether to recommend triggering the kill switch"
    )


SYSTEM_BEHAVIORAL_ANALYSIS = (
    "You are a security analyst specializing in AI agent behavioral analysis.\n"
    "Analyze the following tool call patterns from a monitored AI agent and identify anomalies.\n"
    "For each pattern:\n"
    "1. Compare against the established behavioral baseline\n"
    "2. Identify rate spikes, unusual tool usage, data volume anomalies, off-hours access\n"
    "3. Detect sequential anomalies suggesting recon or exfiltration\n"
    "4. Assess scope violations (agent using tools outside its authorized set)\n"
    "5. Rate the overall risk level and recommend specific actions"
)

SYSTEM_POLICY_RECOMMENDATION = (
    "You are a security policy engineer for AI agent governance.\n"
    "Based on the observed agent behavior and detected anomalies:\n"
    "1. Recommend new firewall policy rules to prevent future violations\n"
    "2. Suggest tightening existing rules where anomalies were detected\n"
    "3. Balance security with operational needs — avoid rules that would block legitimate work\n"
    "4. Consider rate limits, tool whitelists, data volume caps, and time-based restrictions\n"
    "5. Provide confidence scores for each recommendation"
)

SYSTEM_THREAT_ASSESSMENT = (
    "You are a threat intelligence analyst assessing AI agent compromise risk.\n"
    "Given the detected anomalies and policy violations:\n"
    "1. Determine if behavior indicates compromise, misconfig, or drift\n"
    "2. Identify known attack patterns (prompt injection, tool abuse, data exfiltration)\n"
    "3. Assess the blast radius if the agent is compromised\n"
    "4. Recommend immediate containment actions if threat level is high or critical\n"
    "5. Determine whether the kill switch should be triggered"
)
