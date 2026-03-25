"""LLM prompt templates and response schemas for the Attack Campaign Agent."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ── Response schemas ──────────────────────────────────────────────────────


class CampaignPlanOutput(BaseModel):
    """Structured output for campaign planning."""

    recommended_ttps: list[dict[str, Any]] = Field(
        description="Recommended TTPs with technique_id, rationale, priority (1-5)"
    )
    attack_sequence: list[str] = Field(
        description="Ordered list of technique_ids forming the attack chain"
    )
    rationale: str = Field(description="Why this plan is effective for the target scope")
    estimated_duration_minutes: int = Field(description="Estimated campaign duration in minutes")


class TTPAnalysisOutput(BaseModel):
    """Structured output for TTP analysis and prioritisation."""

    prioritized_ttps: list[dict[str, Any]] = Field(
        description="TTPs sorted by effectiveness with technique_id, score, reasoning"
    )
    kill_chain_coverage: dict[str, int] = Field(
        description="Number of techniques per kill chain phase"
    )
    gaps: list[str] = Field(description="Kill chain phases with no technique coverage")
    summary: str = Field(description="Summary of TTP selection quality")


class DefenseGapOutput(BaseModel):
    """Structured output for defense gap analysis."""

    gaps: list[dict[str, Any]] = Field(
        description="Defense gaps with ttp_id, gap_type, severity, description"
    )
    strongest_defenses: list[str] = Field(description="TTPs where defenses performed well")
    weakest_areas: list[str] = Field(description="Kill chain phases with weakest defense coverage")
    overall_posture: str = Field(
        description="Overall defense posture rating: strong, moderate, weak, critical"
    )
    priority_recommendations: list[str] = Field(
        description="Top 5 recommendations ordered by impact"
    )


class CampaignReportOutput(BaseModel):
    """Structured output for the final campaign report."""

    executive_summary: str = Field(
        description="Executive summary of the campaign findings (2-3 sentences)"
    )
    key_findings: list[str] = Field(description="Top findings from the campaign")
    risk_rating: str = Field(description="Overall risk rating: critical, high, medium, low")
    mitre_heatmap: dict[str, str] = Field(
        description="Phase-level coverage: phase → 'covered'|'partial'|'gap'"
    )
    remediation_priorities: list[dict[str, Any]] = Field(
        description="Prioritized remediation items with action, effort, impact"
    )
    next_steps: list[str] = Field(description="Recommended follow-up actions")


# ── Prompt templates ──────────────────────────────────────────────────────

SYSTEM_CAMPAIGN_PLANNING = """\
You are an expert adversary emulation planner designing a multi-step \
attack campaign for an authorized security assessment.

You are given:
- The target scope (platforms, services, network zones, constraints)
- The simulation mode (dry_run, read_only, controlled, full)
- Available MITRE ATT&CK techniques with platform and data-source metadata

Your task is to:
1. Select the most relevant techniques for the target environment
2. Order them into a realistic attack sequence (recon → access → execution → \
persistence → escalation → lateral → collection → exfil → impact)
3. Explain why each technique was chosen
4. Estimate the campaign duration

CONSTRAINTS:
- Respect the simulation mode — dry_run campaigns must not include destructive steps
- Prioritize techniques with high detection-gap potential
- Keep the campaign under 50 steps (blast-radius limit)"""

SYSTEM_TTP_ANALYSIS = """\
You are an expert MITRE ATT&CK analyst prioritizing techniques for a \
campaign simulation.

You are given:
- A list of candidate TTPs with metadata (platform, severity, data sources)
- The target environment description

Your task is to:
1. Score each TTP by effectiveness against this specific target
2. Identify kill-chain coverage gaps
3. Recommend additional techniques if critical phases are uncovered
4. Summarise the overall quality of the TTP selection"""

SYSTEM_DEFENSE_ASSESSMENT = """\
You are an expert defense analyst evaluating how well security controls \
performed against simulated attack techniques.

You are given:
- Simulation step results (success/blocked, detection time, blocking control)
- Defense assessment metrics per TTP

Your task is to:
1. Identify the most critical defense gaps
2. Highlight where defenses performed well
3. Assess the weakest kill-chain phases
4. Provide a prioritized list of remediation recommendations

Be specific: reference technique IDs, detection times, and control names."""

SYSTEM_CAMPAIGN_REPORT = """\
You are a senior security consultant writing the final report for an \
attack campaign simulation.

You are given:
- Campaign metrics (detection rate, prevention rate, mean detection time)
- MITRE coverage heatmap per kill-chain phase
- Defense gap analysis and recommendations

Your task is to:
1. Write a concise executive summary
2. List the top findings with supporting evidence
3. Rate the overall risk
4. Provide a MITRE heatmap showing phase-level coverage
5. Prioritize remediation actions by impact and effort
6. Recommend next steps for improving security posture

Write for a CISO audience: clear, evidence-based, actionable."""
