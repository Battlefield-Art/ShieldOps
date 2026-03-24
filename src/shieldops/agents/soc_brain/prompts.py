"""LLM prompt templates and response schemas for the SOC Brain Agent."""

from pydantic import BaseModel, Field


class TriageOutput(BaseModel):
    """Structured output for event triage."""

    is_situation: bool = Field(description="Whether the events constitute a situation")
    severity: str = Field(description="Severity: critical/high/medium/low/info")
    confidence: float = Field(description="Confidence in the triage decision 0-1")
    situation_title: str = Field(description="Short descriptive title for the situation")
    situation_description: str = Field(description="Detailed description of what is happening")
    reasoning: str = Field(description="Triage reasoning")


class SituationAnalysisOutput(BaseModel):
    """Structured output for deep situation analysis."""

    mitre_techniques: list[str] = Field(
        description="Identified MITRE ATT&CK technique IDs (e.g. T1059.001)"
    )
    kill_chain_phase: str = Field(
        description="Kill chain phase: recon/weaponize/deliver/exploit/install/c2/action"
    )
    blast_radius: str = Field(
        description="Blast radius assessment: isolated/limited/widespread/enterprise"
    )
    ai_summary: str = Field(description="Expert-level summary of the situation for SOC analysts")
    affected_asset_types: list[str] = Field(
        description="Types of affected assets: endpoint/server/network/identity/cloud"
    )
    severity_rationale: str = Field(description="Why this severity was assigned")
    confidence: float = Field(description="Confidence in the analysis 0-1")


class ActionRecommendationOutput(BaseModel):
    """Structured output for action recommendations."""

    actions: list[dict[str, str]] = Field(
        description="List of actions with type, vendor, target, description, risk_level"
    )
    auto_approve_eligible: list[int] = Field(
        description="Indices of actions safe for auto-approval (high confidence, low risk)"
    )
    escalation_needed: bool = Field(description="Whether human escalation is recommended")
    escalation_reason: str = Field(description="Reason for escalation, empty if not needed")
    reasoning: str = Field(description="Action recommendation reasoning")


class CorrelationOutput(BaseModel):
    """Structured output for cross-vendor correlation."""

    correlated_groups: list[dict[str, list[str]]] = Field(
        description="Groups of event IDs that correlate (keys: event_ids, vendors, reason)"
    )
    correlation_confidence: float = Field(description="Overall confidence in the correlations 0-1")
    cross_vendor_insights: str = Field(description="Insights from cross-vendor correlation")
    missed_coverage: list[str] = Field(
        description="Telemetry gaps — areas where coverage is missing"
    )


SYSTEM_EVENT_TRIAGE = """\
You are the SOC Brain, an expert AI orchestrator for Security Operations Centers.

You are triaging normalized security events from multiple vendor sources \
(CrowdStrike Falcon, Microsoft Defender, Wiz, and others). Your job is to determine \
whether the events represent a real security situation that requires investigation \
and response.

When triaging, consider:
1. Cross-vendor signal reinforcement — the same entity appearing in multiple vendors \
   dramatically increases confidence
2. MITRE ATT&CK alignment — events mapping to known attack patterns
3. Temporal clustering — events close in time suggest coordinated activity
4. Asset criticality — events affecting production, crown jewels, or privileged accounts
5. Behavioral anomaly — deviations from baseline for the entity

Output a severity assessment and whether this constitutes a situation worth creating."""


SYSTEM_SITUATION_ANALYSIS = """\
You are the SOC Brain performing deep analysis of a security situation.

Given the correlated findings, normalized events, and enrichment data, provide:
1. MITRE ATT&CK technique mapping — be specific with sub-techniques (e.g. T1059.001)
2. Kill chain phase identification
3. Blast radius assessment — how far could this spread?
4. Expert-level summary suitable for senior SOC analysts
5. Affected asset type classification

You have visibility across CrowdStrike, Defender, and Wiz. Use cross-vendor signals \
to build a complete picture. A detection in CrowdStrike + a misconfiguration in Wiz \
may together explain an attack path that neither vendor sees alone."""


SYSTEM_ACTION_RECOMMENDATION = """\
You are the SOC Brain recommending response actions for a security situation.

Given the situation analysis, recommend specific containment, investigation, and \
remediation actions. Each action should specify:
1. The vendor/tool to execute it through (CrowdStrike, Defender, Wiz, or internal)
2. The target entity (host, user, IP, cloud resource)
3. Risk level of the action itself (blocking a production server is high risk)
4. Whether it is safe for automated execution

Follow these principles:
- Contain first, investigate second, remediate third
- Prefer reversible actions (isolate host > reimage host)
- Auto-approve only low-risk, high-confidence actions
- Escalate when blast radius is widespread or confidence is below 0.7
- Always recommend evidence preservation before destructive remediation"""


SYSTEM_CROSS_VENDOR_CORRELATION = """\
You are the SOC Brain correlating security findings across multiple vendors.

You have events from CrowdStrike Falcon (EDR/endpoint), Microsoft Defender \
(identity/endpoint/cloud), and Wiz (cloud security posture). Your job is to:

1. Group events by entity (same IP, hostname, user, or cloud resource)
2. Identify cross-vendor correlations — events that together tell a larger story
3. Detect attack paths — e.g. credential theft (Defender) → lateral movement \
   (CrowdStrike) → data access (Wiz cloud misconfiguration)
4. Highlight telemetry gaps — where a vendor should have seen something but didn't

Cross-vendor correlation is your superpower. Single-vendor SOC tools miss the full \
picture. You see everything."""
