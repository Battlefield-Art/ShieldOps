"""LLM prompt templates and response schemas for Autonomous XDR.

Provides system prompts for cross-domain correlation, automated
investigation, and executive reporting — all vendor-neutral.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured Output Schemas ──────────────────────────────


class CorrelationOutput(BaseModel):
    """LLM output for cross-domain signal correlation."""

    correlation_description: str = Field(
        description="Narrative describing the correlation",
    )
    kill_chain_phase: str = Field(
        description="Kill chain phase (recon/access/exec/persist/"
        "escalate/lateral/collect/exfil/impact)",
    )
    confidence: float = Field(
        description="Confidence score 0.0-1.0",
    )
    recommended_priority: str = Field(
        description="Priority: critical/high/medium/low",
    )


class InvestigationOutput(BaseModel):
    """LLM output for automated investigation."""

    root_cause: str = Field(
        description="Root cause of the campaign",
    )
    entry_point: str = Field(
        description="Initial entry vector",
    )
    blast_radius: str = Field(
        description="Blast radius assessment",
    )
    containment_urgency: str = Field(
        description="Urgency: immediate/high/medium/low",
    )
    recommended_actions: list[str] = Field(
        default_factory=list,
        description="Ordered containment actions",
    )


class ReportOutput(BaseModel):
    """LLM output for executive XDR report."""

    executive_summary: str = Field(
        description="1-2 sentence executive summary",
    )
    threat_narrative: str = Field(
        description="Human-readable attack narrative",
    )
    risk_level: str = Field(
        description="Overall risk: critical/high/medium/low",
    )
    key_findings: list[str] = Field(
        default_factory=list,
        description="Top findings for leadership",
    )
    recommended_next_steps: list[str] = Field(
        default_factory=list,
        description="Prioritized next steps",
    )


# ── System Prompts ─────────────────────────────────────────

SYSTEM_CORRELATE = """\
You are an expert cross-domain threat correlation analyst \
for an autonomous XDR platform.

Given normalized alerts from multiple vendors and domains \
(endpoint, network, cloud, identity, email, IoT):

1. Identify shared entities (IPs, users, assets, hashes)
2. Map alert sequences to MITRE ATT&CK kill chain phases
3. Score correlation confidence based on entity overlap, \
temporal proximity, and technique chaining
4. Flag cross-domain patterns that single-vendor XDR would miss

You correlate signals from CrowdStrike, Microsoft Defender, \
SentinelOne, Carbon Black, Wiz, Prisma Cloud, Okta, and \
Entra ID — vendor-neutral analysis is your advantage."""

SYSTEM_INVESTIGATE = """\
You are an autonomous XDR investigation engine.

Given a detected multi-stage campaign with correlated alerts:

1. Determine the root cause and initial entry point
2. Trace the lateral movement path across domains
3. Identify all compromised assets and identities
4. Assess blast radius — how far could the attacker reach
5. Recommend containment actions ordered by urgency

Be precise. Every claim must link to specific alert evidence. \
Prioritize containment of active threats over forensic depth."""

SYSTEM_REPORT = """\
You are a security reporting specialist for an autonomous \
XDR platform.

Given investigation results and campaign detections:

1. Write a concise executive summary (1-2 sentences)
2. Build a human-readable threat narrative
3. Assess overall organizational risk level
4. List key findings for leadership review
5. Recommend prioritized next steps

Use clear, non-technical language for executives. \
Reference MITRE techniques by name, not just ID."""
