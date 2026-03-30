"""LLM prompt templates and response schemas for the
Threat Hunt Orchestrator Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class HypothesisGenerationOutput(BaseModel):
    """Structured output for hypothesis generation."""

    hypotheses: list[dict[str, str]] = Field(
        description=("List of hunt hypotheses with statement, tactic, and priority"),
    )
    mitre_techniques: list[str] = Field(
        description="MITRE ATT&CK technique IDs",
    )
    recommended_sources: list[str] = Field(
        description="Data sources to query",
    )
    confidence: float = Field(
        description="Overall confidence in hypotheses 0-1",
    )


class DataAnalysisOutput(BaseModel):
    """Structured output for evidence analysis."""

    anomalies_detected: int = Field(
        description="Number of anomalies found",
    )
    patterns: list[str] = Field(
        description="Identified suspicious patterns",
    )
    risk_score: float = Field(
        description="Aggregate risk score 0-10",
    )
    summary: str = Field(
        description="Analysis summary for analysts",
    )


class FindingValidationOutput(BaseModel):
    """Structured output for finding validation."""

    validated: bool = Field(
        description="Whether finding is confirmed",
    )
    severity: str = Field(
        description="Severity: critical/high/medium/low",
    )
    confidence: float = Field(
        description="Validation confidence 0-1",
    )
    mitre_mapping: str = Field(
        description="Mapped MITRE ATT&CK technique ID",
    )
    description: str = Field(
        description="Detailed finding description",
    )
    affected_assets: list[str] = Field(
        description="Affected asset identifiers",
    )


class HuntReportOutput(BaseModel):
    """Structured output for final hunt report."""

    executive_summary: str = Field(
        description="Executive summary of hunt campaign",
    )
    threat_found: bool = Field(
        description="Whether confirmed threats exist",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )
    mitre_coverage: list[str] = Field(
        description="MITRE techniques investigated",
    )
    effectiveness_rating: str = Field(
        description="Hunt effectiveness: high/medium/low",
    )


# --- System prompts ---


SYSTEM_HYPOTHESIS = """\
You are an expert threat hunt orchestrator generating \
hunting hypotheses.

Given the campaign scope, target MITRE ATT&CK tactics, \
and available data sources:
1. Generate specific, testable hypotheses about adversary \
activity
2. Map each hypothesis to MITRE ATT&CK techniques
3. Identify the data sources required for validation
4. Prioritize hypotheses by likelihood and impact

Focus on threats that evade automated detections: \
living-off-the-land, slow-and-low exfiltration, \
supply chain compromise, and identity-based attacks."""


SYSTEM_ANALYSIS = """\
You are an expert threat analyst reviewing collected \
evidence from a proactive hunt campaign.

Given the raw evidence from multiple data sources:
1. Identify anomalous patterns and deviations from \
baseline behavior
2. Correlate signals across sources to detect multi-stage \
attacks
3. Score risk based on MITRE ATT&CK tactic progression
4. Distinguish confirmed threats from benign anomalies

Be precise and evidence-based. False positives erode \
analyst trust."""


SYSTEM_VALIDATION = """\
You are an expert threat validator confirming or \
refuting hunt findings against MITRE ATT&CK.

Given an individual finding with supporting evidence:
1. Validate whether the activity represents a true \
positive threat
2. Map to the specific MITRE ATT&CK technique and tactic
3. Assess severity based on blast radius and attacker \
capability
4. Identify all affected assets for containment scoping

Err on the side of caution for critical infrastructure."""


SYSTEM_REPORT = """\
You are an expert threat hunt reporter synthesizing \
campaign results.

Given the full hunt campaign (hypotheses, evidence, \
validated findings):
1. Produce an executive summary for security leadership
2. List actionable recommendations prioritized by risk
3. Summarize MITRE ATT&CK coverage achieved
4. Rate overall hunt effectiveness

Write clearly for both technical and non-technical \
audiences."""
