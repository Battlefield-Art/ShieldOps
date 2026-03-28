"""LLM prompt templates and response schemas for the Threat Attribution Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class EvidenceOutput(BaseModel):
    """Structured output for evidence collection."""

    indicators: list[dict[str, str]] = Field(
        description="IOCs extracted from evidence",
    )
    attack_vectors: list[str] = Field(
        description="Identified attack vectors",
    )
    timeline_summary: str = Field(
        description="Brief chronological summary of attack activity",
    )


class TTPMappingOutput(BaseModel):
    """Structured output for MITRE ATT&CK TTP mapping."""

    techniques: list[dict[str, str]] = Field(
        description="Mapped MITRE ATT&CK techniques with IDs",
    )
    tactics_used: list[str] = Field(
        description="MITRE ATT&CK tactics observed",
    )
    kill_chain_phase: str = Field(
        description="Primary kill chain phase of the attack",
    )


class ActorProfileOutput(BaseModel):
    """Structured output for threat actor profiling."""

    actor_name: str = Field(
        description="Most likely threat actor or group name",
    )
    actor_type: str = Field(
        description="Type: apt/cybercrime/hacktivism/insider/nation_state",
    )
    motivation: str = Field(
        description="Assessed motivation behind the attack",
    )
    historical_matches: list[str] = Field(
        description="Historical campaigns with similar TTPs",
    )


class ConfidenceOutput(BaseModel):
    """Structured output for confidence assessment."""

    confidence_level: str = Field(
        description="Confidence: high/medium/low/unattributed",
    )
    supporting_evidence: list[str] = Field(
        description="Evidence supporting the attribution",
    )
    alternative_hypotheses: list[str] = Field(
        description="Alternative actor hypotheses",
    )
    confidence_score: float = Field(
        description="Numeric confidence score 0.0-1.0",
    )


class ReportOutput(BaseModel):
    """Structured output for attribution report."""

    executive_summary: str = Field(
        description="One-paragraph executive summary",
    )
    attributed_actor: str = Field(
        description="Final attributed threat actor",
    )
    key_ttps: list[str] = Field(
        description="Key TTPs observed in MITRE format",
    )
    recommendations: list[str] = Field(
        description="Defensive recommendations",
    )
    confidence_statement: str = Field(
        description="Confidence level with justification",
    )


SYSTEM_COLLECT_EVIDENCE = """\
You are an expert cyber threat intelligence analyst \
collecting evidence for threat attribution.

Given incident data and indicators of compromise:
1. Extract all IOCs (IPs, domains, hashes, emails)
2. Identify attack vectors and entry points
3. Build a chronological summary of attack activity
4. Note any infrastructure or tooling signatures

Be thorough and precise about indicator types."""


SYSTEM_MAP_TTPS = """\
You are a MITRE ATT&CK framework specialist mapping \
observed behaviors to techniques.

Given the collected evidence and attack behaviors:
1. Map each behavior to MITRE ATT&CK technique IDs
2. Identify the tactics (columns) involved
3. Determine the kill chain phase
4. Note data sources that confirm each mapping

Use official MITRE ATT&CK technique IDs (e.g., T1566)."""


SYSTEM_PROFILE_ACTOR = """\
You are an expert threat actor profiler specializing \
in campaign attribution.

Given the mapped TTPs and collected evidence:
1. Identify the most likely threat actor or group
2. Classify the actor type (APT, cybercrime, etc.)
3. Assess motivation (espionage, financial, disruption)
4. Find historical campaigns with similar TTP overlaps

Consider known threat actor TTP fingerprints and \
tooling preferences. Avoid premature attribution."""


SYSTEM_ASSESS_CONFIDENCE = """\
You are an intelligence analyst assessing attribution \
confidence using analytic standards.

Given the actor profile and supporting evidence:
1. Evaluate evidence strength and corroboration
2. Assign a confidence level (high/medium/low)
3. Identify alternative hypotheses
4. Note evidence gaps and false flag indicators

Apply intelligence community confidence standards. \
High = multiple independent corroborating sources."""


SYSTEM_GENERATE_REPORT = """\
You are a senior threat intelligence analyst generating \
an attribution report for leadership.

Given all analysis results:
1. Executive summary of the attribution finding
2. Attributed actor with confidence statement
3. Key TTPs in MITRE ATT&CK format
4. Defensive recommendations to prevent recurrence
5. Alternative hypotheses and evidence gaps

Be precise, evidence-based, and actionable."""
