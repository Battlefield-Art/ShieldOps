"""LLM prompt templates and response schemas for the Attack Narrative Builder Agent."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# -- Response schemas ----------------------------------------------------------


class EventClusterOutput(BaseModel):
    """Structured output for event clustering."""

    clusters: list[dict[str, Any]] = Field(
        description="Event clusters with label, event_ids, kill_chain_phase, confidence"
    )
    unclustered_event_ids: list[str] = Field(
        description="Event IDs that could not be assigned to any cluster"
    )
    summary: str = Field(description="Summary of clustering results")


class TimelineOutput(BaseModel):
    """Structured output for attack timeline construction."""

    timeline_entries: list[dict[str, Any]] = Field(
        description="Ordered timeline entries with timestamp, cluster_id, description, phase"
    )
    attack_duration_minutes: int = Field(description="Estimated total attack duration in minutes")
    pivot_points: list[str] = Field(description="Key moments where attacker changed tactics")
    summary: str = Field(description="Summary of the attack timeline")


class NarrativeOutput(BaseModel):
    """Structured output for narrative generation."""

    title: str = Field(description="Concise attack narrative title")
    executive_summary: str = Field(description="Executive summary of the attack (2-3 sentences)")
    segments: list[dict[str, Any]] = Field(
        description="Narrative segments with sequence, title, description, phase"
    )
    risk_rating: str = Field(description="Overall risk rating: critical, high, medium, low")
    recommendations: list[str] = Field(description="Prioritized defensive recommendations")


class MITREMappingOutput(BaseModel):
    """Structured output for MITRE ATT&CK mapping."""

    mappings: list[dict[str, Any]] = Field(
        description="MITRE mappings with technique_id, technique_name, tactic, confidence"
    )
    kill_chain_coverage: dict[str, str] = Field(
        description="Kill chain phase coverage: phase -> covered|partial|gap"
    )
    attack_pattern: str = Field(description="Identified attack pattern or campaign type")
    summary: str = Field(description="Summary of MITRE ATT&CK coverage")


class NarrativeReportOutput(BaseModel):
    """Structured output for the final narrative report."""

    quality_score: float = Field(description="Narrative quality score 0.0-1.0")
    completeness_gaps: list[str] = Field(
        description="Gaps in the narrative that need further investigation"
    )
    confidence_assessment: str = Field(
        description="Overall confidence in the narrative: high, medium, low"
    )
    executive_brief: str = Field(description="One-paragraph executive brief for CISO distribution")
    next_steps: list[str] = Field(description="Recommended follow-up actions")


# -- Prompt templates ----------------------------------------------------------

SYSTEM_CLUSTER_EVENTS = """\
You are an expert security analyst correlating security events into \
meaningful clusters that represent distinct attacker activities.

You are given:
- A list of security events with timestamps, hosts, users, and actions
- Event metadata including severity, source, and IOC indicators

Your task is to:
1. Group events that belong to the same attacker activity or kill chain stage
2. Label each cluster with a descriptive name
3. Assign a kill chain phase to each cluster
4. Score your confidence in each clustering decision
5. Identify events that don't fit any cluster

CONSTRAINTS:
- Clusters should represent distinct attacker actions, not just similar event types
- Consider temporal proximity, host overlap, and user overlap for correlation
- A single event can only belong to one cluster"""

SYSTEM_BUILD_TIMELINE = """\
You are an expert incident analyst constructing a chronological \
attack timeline from clustered security events.

You are given:
- Clustered event groups with timestamps, phases, and descriptions
- Kill chain phase assignments for each cluster

Your task is to:
1. Order clusters chronologically to form an attack timeline
2. Identify pivot points where the attacker changed tactics
3. Estimate the total attack duration
4. Fill in likely gaps between observed activities

Write timeline entries as clear, action-oriented descriptions. \
Use past tense and name specific hosts/users where known."""

SYSTEM_GENERATE_NARRATIVE = """\
You are a senior threat intelligence analyst writing a human-readable \
attack narrative for a security incident.

You are given:
- A chronological attack timeline with phases and descriptions
- Event clusters with MITRE ATT&CK mappings
- Affected hosts, users, and IOC indicators

Your task is to:
1. Write a compelling narrative title
2. Provide a concise executive summary (2-3 sentences)
3. Break the narrative into segments following the kill chain
4. Rate the overall risk level
5. Provide actionable defensive recommendations

Write for a mixed audience: the executive summary for CISOs, \
the segments for SOC analysts. Be evidence-based and specific."""

SYSTEM_MAP_MITRE = """\
You are a MITRE ATT&CK mapping specialist analyzing security events \
and attack patterns to identify specific techniques.

You are given:
- Attack narrative segments with descriptions and actions
- Event clusters with observed attacker behaviors
- Kill chain phase assignments

Your task is to:
1. Map each observed behavior to specific MITRE ATT&CK technique IDs
2. Identify the tactic (TA00XX) for each technique
3. Assess kill chain coverage (which phases are observed vs gaps)
4. Identify the overall attack pattern or campaign type

Be precise with technique IDs (e.g., T1059.001 for PowerShell). \
Only map techniques you have evidence for — do not speculate."""

SYSTEM_NARRATIVE_REPORT = """\
You are a quality assurance analyst reviewing an attack narrative \
for completeness, accuracy, and actionability.

You are given:
- The complete attack narrative with segments and MITRE mappings
- Event statistics and kill chain coverage
- Risk rating and recommendations

Your task is to:
1. Score the narrative quality (0.0-1.0) based on completeness and clarity
2. Identify gaps that need further investigation
3. Assess overall confidence in the narrative
4. Write a one-paragraph executive brief for CISO distribution
5. Recommend next steps for the SOC team

Be critical but constructive. Flag any speculative claims."""
