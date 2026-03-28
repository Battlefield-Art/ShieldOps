"""API Rate Limiter — LLM prompt templates."""

from pydantic import BaseModel, Field


class AbuseAnalysisResult(BaseModel):
    """Structured output from LLM-assisted abuse pattern analysis."""

    summary: str = Field(description="Brief summary of detected abuse patterns")
    pattern_count: int = Field(description="Number of confirmed abuse patterns")
    risk_level: str = Field(description="Overall risk level: low, medium, high, critical")
    pattern_details: list[str] = Field(description="Detailed description of each abuse pattern")
    recommended_actions: list[str] = Field(description="Recommended rate limiting actions")


class AdaptiveRuleResult(BaseModel):
    """Structured output from LLM-assisted adaptive rule generation."""

    summary: str = Field(description="Brief summary of recommended rate limit adjustments")
    new_rules: list[str] = Field(description="New rate limit rules to apply")
    adjusted_limits: list[str] = Field(description="Existing limits to adjust with rationale")
    confidence: float = Field(description="Confidence in recommendations 0.0-1.0")


class ThreatClassificationResult(BaseModel):
    """Structured output from LLM-assisted threat classification."""

    summary: str = Field(description="Brief threat classification summary")
    threat_level: str = Field(description="Threat level: none, low, medium, high, critical")
    attack_type: str = Field(description="Primary attack type if identified")
    coordinated: bool = Field(description="Whether the attack appears coordinated")
    immediate_actions: list[str] = Field(description="Actions to take immediately")


SYSTEM_ABUSE_ANALYSIS = (
    "You are an API security analyst specializing in abuse detection.\n"
    "Analyze the following API traffic patterns and identify abuse:\n"
    "1. Detect credential stuffing (high auth failure rates, "
    "rotating IPs, sequential usernames)\n"
    "2. Identify API scraping (systematic endpoint enumeration, "
    "high request rates, data harvesting)\n"
    "3. Spot brute force attacks (repeated auth attempts, "
    "common password patterns)\n"
    "4. Detect distributed attacks (same pattern across "
    "multiple IPs or client IDs)\n"
    "5. Identify slowloris patterns (many open connections, "
    "slow request completion)\n"
    "6. Rate the overall risk and recommend specific actions"
)

SYSTEM_ADAPTIVE_RULES = (
    "You are an API rate limiting engineer.\n"
    "Based on observed traffic patterns and detected abuse:\n"
    "1. Recommend adaptive rate limits per client and endpoint\n"
    "2. Set burst limits for legitimate traffic spikes\n"
    "3. Propose graduated response (throttle before block)\n"
    "4. Balance protection with user experience\n"
    "5. Consider time-of-day and geographic patterns\n"
    "6. Provide confidence scores for each recommendation"
)

SYSTEM_THREAT_CLASSIFICATION = (
    "You are a threat intelligence analyst assessing API attack risk.\n"
    "Given the detected abuse patterns and client profiles:\n"
    "1. Classify the primary attack type\n"
    "2. Determine if the attack is coordinated or opportunistic\n"
    "3. Assess the blast radius and data exposure risk\n"
    "4. Recommend immediate containment actions\n"
    "5. Identify indicators of compromise for future detection"
)
