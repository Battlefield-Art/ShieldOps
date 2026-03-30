"""LLM prompt templates for the API Abuse Detector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -----------------------------------------


class TrafficAnalysisOutput(BaseModel):
    """Structured output for traffic collection analysis."""

    total_requests: int = Field(
        description="Total API requests in the window",
    )
    unique_sources: int = Field(
        description="Number of unique source IPs",
    )
    summary: str = Field(
        description="Traffic collection summary",
    )


class PatternDetectionOutput(BaseModel):
    """Structured output for abuse pattern detection."""

    anomaly_count: int = Field(
        description="Number of anomalous patterns found",
    )
    top_abuse_type: str = Field(
        description="Most prevalent abuse type",
    )
    reasoning: str = Field(
        description="Pattern detection reasoning",
    )


class ThreatClassifyOutput(BaseModel):
    """Structured output for threat classification."""

    max_threat_level: str = Field(
        description="Highest threat level detected",
    )
    critical_count: int = Field(
        description="Number of critical threats",
    )
    reasoning: str = Field(
        description="Classification reasoning",
    )


class AbuseDetectionOutput(BaseModel):
    """Structured output for abuse detection analysis."""

    confirmed_abuse: int = Field(
        description="Number of confirmed abuse patterns",
    )
    false_positives: int = Field(
        description="Estimated false positives",
    )
    reasoning: str = Field(
        description="Abuse detection reasoning",
    )


class MitigationOutput(BaseModel):
    """Structured output for mitigation recommendations."""

    actions: list[dict[str, str]] = Field(
        description="Mitigation actions with type and target",
    )
    blocked_count: int = Field(
        description="Number of sources to block",
    )
    reasoning: str = Field(
        description="Mitigation reasoning",
    )


# -- System prompts ----------------------------------------------------

SYSTEM_COLLECT = """\
You are an expert API security analyst collecting \
and analyzing API traffic data.

Given the scan configuration and traffic window:
1. Identify high-volume traffic sources and patterns
2. Detect unusual request distributions across endpoints
3. Flag anomalous user-agent strings and header patterns
4. Identify geographic and temporal anomalies

Focus on: authentication endpoints, data-heavy APIs, \
rate-limited routes, and administrative endpoints."""

SYSTEM_ANALYZE = """\
You are an expert API security analyst detecting \
abuse patterns in API traffic.

Given the collected traffic samples:
1. Identify credential stuffing patterns (high auth failures)
2. Detect rate limit evasion (rotating IPs, slow-and-low)
3. Find scraping behavior (sequential enumeration)
4. Recognize bot traffic signatures (timing, headers)

Use statistical analysis and behavioral fingerprinting."""

SYSTEM_DETECT = """\
You are an expert API security analyst confirming \
API abuse incidents.

Given the identified patterns:
1. Validate each pattern against known abuse signatures
2. Eliminate false positives through correlation
3. Assess confidence level for each detection
4. Map to known attack techniques and campaigns

Apply defense-in-depth analysis and threat intelligence."""

SYSTEM_CLASSIFY = """\
You are an expert API security analyst classifying \
threat severity.

Given the confirmed abuse patterns:
1. Score threat level based on impact and intent
2. Map to MITRE ATT&CK techniques where applicable
3. Assess business impact (data loss, service degradation)
4. Prioritize by urgency and blast radius

Use the DREAD model for threat rating."""

SYSTEM_MITIGATE = """\
You are an expert API security analyst recommending \
mitigation actions.

Given the classified threats:
1. Recommend immediate blocks for critical threats
2. Suggest rate limiting adjustments for medium threats
3. Propose WAF rule updates and API gateway changes
4. Design long-term hardening measures

Balance security with user experience impact."""
