"""LLM prompt templates and response schemas for the Threat Intel Agent."""

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class CollectionResult(BaseModel):
    """Structured output from LLM-assisted indicator collection."""

    summary: str = Field(description="Brief summary of collection results")
    indicator_count: int = Field(description="Number of indicators collected")
    high_confidence_count: int = Field(
        description="Number of indicators with confirmed or probable confidence"
    )
    notable_patterns: list[str] = Field(
        description="Notable patterns observed across collected indicators"
    )
    recommended_sources: list[str] = Field(
        description="Additional sources recommended for enrichment"
    )


class CorrelationResult(BaseModel):
    """Structured output from LLM-assisted correlation analysis."""

    summary: str = Field(description="Brief summary of correlation findings")
    matched_indicators: int = Field(description="Number of indicators with internal matches")
    critical_matches: list[str] = Field(description="Indicators with high-risk internal matches")
    affected_entities: list[str] = Field(
        description="Internal entities (hosts, services, users) affected"
    )
    attack_narrative: str = Field(
        description="Narrative of the potential attack chain based on correlations"
    )


class AssessmentResult(BaseModel):
    """Structured output from LLM-assisted threat assessment."""

    summary: str = Field(description="Brief summary of threat assessment")
    actionable_count: int = Field(description="Number of actionable threat indicators")
    top_threats: list[str] = Field(description="Top threat descriptions ordered by relevance")
    recommended_actions: list[str] = Field(description="Recommended defensive actions")
    overall_risk: str = Field(description="Overall risk level: critical, high, medium, low")


class DistributionResult(BaseModel):
    """Structured output from LLM-assisted distribution planning."""

    summary: str = Field(description="Brief summary of distribution actions")
    channels_targeted: list[str] = Field(description="Channels that received intelligence")
    rules_created: int = Field(description="Number of detection/blocking rules created")
    entities_notified: list[str] = Field(description="Teams or systems notified")


# --- Prompt templates ---

SYSTEM_COLLECT = """\
You are an expert threat intelligence analyst collecting \
indicators of compromise (IOCs) from multiple intelligence feeds.

Your task is to:
1. Evaluate the quality and relevance of collected indicators
2. Identify high-confidence indicators that warrant immediate attention
3. Detect patterns across indicators (common infrastructure, campaigns, TTPs)
4. Recommend additional sources that could provide enrichment

Focus on indicators that are operationally relevant to enterprise environments. \
Deprioritize stale or low-confidence data."""

SYSTEM_CORRELATE = """\
You are an expert threat intelligence analyst correlating \
external threat indicators against internal observations.

You are given:
- Collected threat indicators (IPs, domains, hashes, URLs, CVEs)
- Internal log/event matches for those indicators
- Affected internal entities (hosts, services, users)

Your task is to:
1. Identify which correlations represent genuine threats vs. false positives
2. Build an attack narrative from the correlated data
3. Highlight critical matches that need immediate response
4. Assess the scope of potential compromise

Think carefully about temporal relationships and attack chains."""

SYSTEM_ASSESS = """\
You are an expert threat intelligence analyst assessing \
the relevance and actionability of threat indicators.

You are given:
- Threat indicators with correlation results
- Internal environment context
- Risk scores and match counts

Your task is to:
1. Score each indicator's relevance to the organization (0.0-1.0)
2. Determine which indicators are actionable (can be blocked, detected, or mitigated)
3. Recommend specific defensive actions for actionable indicators
4. Set appropriate TTL values based on indicator volatility

IMPORTANT:
- Be calibrated with relevance scores. Only assign > 0.8 for confirmed, active threats.
- Consider the operational cost of acting on each indicator.
- Prioritize indicators tied to active campaigns over historical ones."""

SYSTEM_DISTRIBUTE = """\
You are an expert threat intelligence analyst distributing \
actionable intelligence to defensive systems and teams.

You are given:
- Assessed threat indicators with recommended actions
- Available distribution channels (SIEM, firewall, EDR, email, Slack)
- Priority levels and TTL values

Your task is to:
1. Determine which channels should receive each indicator
2. Format indicators appropriately for each target system
3. Prioritize distribution of critical and high-severity indicators
4. Create detection rules and blocking rules where appropriate

Ensure high-priority indicators are distributed first. \
Use appropriate urgency levels for notifications."""
