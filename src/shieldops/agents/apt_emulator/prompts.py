"""LLM prompt templates and response schemas for APT Emulator."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# -----------------------------------------------------------
# Response schemas
# -----------------------------------------------------------


class CampaignDesignOutput(BaseModel):
    """LLM output for campaign design."""

    campaign_name: str = Field(description="Name of the emulation campaign")
    techniques: list[str] = Field(description="MITRE ATT&CK technique IDs to emulate")
    objectives: list[str] = Field(description="Campaign objectives")
    safety_constraints: list[str] = Field(description="Safety guardrails for safe emulation")


class ReconAnalysisOutput(BaseModel):
    """LLM output for recon analysis."""

    exposed_services: list[str] = Field(description="Services found exposed")
    risk_assessment: str = Field(description="Risk assessment of recon findings")
    next_techniques: list[str] = Field(description="Recommended next techniques")


class CampaignReportOutput(BaseModel):
    """LLM output for final campaign report."""

    executive_summary: str = Field(description="Executive summary of the campaign")
    phases_summary: list[dict[str, Any]] = Field(description="Per-phase results summary")
    top_recommendations: list[str] = Field(description="Top defense recommendations")
    overall_grade: str = Field(description="A-F grade for defense posture")


# -----------------------------------------------------------
# Prompt templates
# -----------------------------------------------------------

SYSTEM_CAMPAIGN_DESIGN = """\
You are an expert adversary emulation planner designing safe \
APT campaign simulations. Given an APT group name and target \
environment, design a campaign that covers recon, initial \
access, persistence, lateral movement, and exfiltration.

All simulations are SAFE: log injection, traffic replay, \
atomic tests only. NEVER generate real exploits.

Include MITRE ATT&CK technique IDs for each phase."""

SYSTEM_RECON_ANALYSIS = """\
You are a threat intelligence analyst reviewing \
reconnaissance simulation results. Assess which services \
are exposed, the risk level, and recommend follow-on \
techniques from the ATT&CK framework.

Focus on what a real APT group would target next."""

SYSTEM_CAMPAIGN_REPORT = """\
You are a senior security consultant writing the final \
APT emulation campaign report. Summarize results across \
all phases, grade the defense posture, and provide \
actionable recommendations.

Use hard numbers: phases blocked vs evaded, detection \
rates, response times. Be direct and actionable."""
