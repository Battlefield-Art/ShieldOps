"""LLM prompt templates and response schemas for the Session Hijack Detector Agent."""

from pydantic import BaseModel, Field


class AnomalyAnalysisOutput(BaseModel):
    """Structured output for session anomaly analysis."""

    hijack_types_detected: list[str] = Field(
        description="Types of hijacking detected: token_theft, "
        "cookie_manipulation, impossible_travel, session_replay, "
        "concurrent_geo, session_fixation, sidejacking",
    )
    confidence: float = Field(
        description="Overall detection confidence 0.0-1.0",
    )
    mitre_techniques: list[str] = Field(
        description="MITRE ATT&CK technique IDs (e.g. T1539, T1550.004)",
    )
    reasoning: str = Field(
        description="Analysis reasoning",
    )


class CorrelationOutput(BaseModel):
    """Structured output for indicator correlation."""

    confirmed_hijack_count: int = Field(
        description="Number of confirmed session hijacks",
    )
    attack_clusters: list[dict[str, str]] = Field(
        description="Groups of correlated indicators forming attack patterns",
    )
    risk_level: str = Field(
        description="Overall risk: critical, high, medium, low, info",
    )
    reasoning: str = Field(
        description="Correlation reasoning",
    )


class RiskAssessmentOutput(BaseModel):
    """Structured output for risk assessment."""

    risk_score: float = Field(
        description="Risk score 0-100",
    )
    auto_respond: bool = Field(
        description="Whether to auto-respond without approval",
    )
    recommended_actions: list[dict[str, str]] = Field(
        description="Recommended response actions",
    )
    reasoning: str = Field(
        description="Risk assessment reasoning",
    )


SYSTEM_ANALYZE = """\
You are an expert session security analyst specializing in \
detecting session hijacking attacks. Analyze session events \
for indicators of token theft, cookie manipulation, \
impossible travel, session replay, and concurrent sessions \
from different geolocations.

Given the session telemetry:
1. Identify hijack type (token_theft, cookie_manipulation, \
impossible_travel, session_replay, concurrent_geo, \
session_fixation, sidejacking)
2. Map to MITRE ATT&CK techniques (T1539 Steal Web Session \
Cookie, T1550.004 Web Session Cookie, T1185 Browser \
Session Hijacking)
3. Assess detection confidence
4. Flag impossible travel (speed > 500 km/h between logins)
5. Detect concurrent sessions from distant geolocations"""


SYSTEM_CORRELATE = """\
You are an expert threat correlation analyst. Correlate \
session hijack indicators to confirm active attacks and \
distinguish true positives from benign anomalies.

Given the indicators:
1. Group related indicators by attack pattern
2. Confirm or dismiss each hijack hypothesis
3. Identify multi-session attacks by same threat actor
4. Assess overall risk level

Consider VPN usage, mobile roaming, and shared IP pools \
as benign explanations before confirming hijack."""


SYSTEM_ASSESS_RISK = """\
You are an expert session security risk assessor. Evaluate \
the risk of confirmed session hijacking and recommend \
response actions.

Given confirmed hijacks and indicators:
1. Score risk (0-100)
2. Determine if auto-response is warranted \
(confidence > 0.85 = auto, 0.5-0.85 = approval, \
< 0.5 = monitor)
3. Recommend specific actions: invalidate_session, \
force_reauth, revoke_token, block_ip, notify_user
4. Prioritize actions by impact and urgency"""
