"""LLM prompt templates and response schemas for the Situation Composer Agent."""

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Structured output schemas
# ---------------------------------------------------------------------------


class CorrelationOutput(BaseModel):
    """Structured output for alert correlation."""

    correlated_groups: list[dict[str, list[str]]] = Field(
        description="Groups of alert IDs that correlate (keys: alert_ids, vendors, reason)"
    )
    kill_chain_phases: list[str] = Field(
        description="Kill chain phases identified in the correlated groups"
    )
    correlation_confidence: float = Field(description="Overall confidence in the correlations 0-1")
    cross_vendor_insights: str = Field(description="Insights from cross-vendor correlation")


class NarrativeOutput(BaseModel):
    """Structured output for narrative construction."""

    title: str = Field(description="Short descriptive title for the situation")
    executive_summary: str = Field(
        description="Executive-level summary of the situation for leadership"
    )
    kill_chain_mapping: dict[str, list[str]] = Field(
        description="Mapping of kill chain phase to alert IDs"
    )
    timeline_events: list[dict[str, str]] = Field(
        description="Ordered timeline entries with timestamp, event, source"
    )
    ioc_list: list[str] = Field(description="Indicators of compromise found")
    mitre_techniques: list[str] = Field(description="MITRE ATT&CK technique IDs (e.g. T1059.001)")
    confidence: float = Field(description="Confidence in the narrative 0-1")


class ActionRecommendationOutput(BaseModel):
    """Structured output for response action recommendations."""

    actions: list[dict[str, str]] = Field(
        description=(
            "List of recommended actions with keys: "
            "action_type, target, description, risk_level, estimated_impact"
        )
    )
    auto_executable_indices: list[int] = Field(
        description="Indices of actions safe for automated execution"
    )
    escalation_needed: bool = Field(description="Whether human escalation is recommended")
    reasoning: str = Field(description="Action recommendation reasoning")


class SituationSummaryOutput(BaseModel):
    """Structured output for final situation summary."""

    severity: str = Field(description="Severity: critical/high/medium/low/info")
    status: str = Field(description="Recommended initial status for the situation")
    one_liner: str = Field(description="One-line summary for the situations queue")
    assigned_team: str = Field(description="Recommended team assignment (soc/ir/devops/identity)")
    confidence: float = Field(description="Overall confidence in the composed situation 0-1")


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_ALERT_CORRELATION = """\
You are the Situation Composer, an expert AI agent for aggregating security alerts \
into coherent situations.

You are correlating alerts from multiple security vendors (CrowdStrike, Microsoft \
Defender, Wiz, Splunk, Elastic, Datadog, PagerDuty, and others). Your job is to \
identify which alerts are related and group them into correlated clusters.

When correlating, consider:
1. Entity overlap — alerts sharing source IPs, destination IPs, hostnames, or users \
   are likely related
2. Temporal proximity — alerts within a narrow time window suggest the same incident
3. Kill chain progression — alerts mapping to sequential kill chain phases indicate \
   an evolving attack
4. Campaign indicators — shared IOCs, MITRE techniques, or TTP patterns
5. Cross-vendor reinforcement — the same activity seen by multiple vendors dramatically \
   increases confidence

Group alerts that belong together and identify the kill chain phases they map to."""


SYSTEM_NARRATIVE_BUILDER = """\
You are the Situation Composer constructing a kill-chain narrative from correlated \
security alerts.

Given the correlated alert groups, build a coherent narrative that tells the story of \
what happened:
1. Map each alert group to the appropriate Cyber Kill Chain phase
2. Construct a timeline from earliest to latest event
3. Extract IOCs (IPs, domains, hashes, file paths, registry keys)
4. Map to MITRE ATT&CK techniques — be specific with sub-techniques (e.g. T1059.001)
5. Write an executive summary suitable for CISO-level reporting
6. Identify all affected assets (hosts, users, cloud resources)

The narrative must be actionable. SOC analysts will use it to understand the full \
scope of the incident without having to read dozens of individual alerts."""


SYSTEM_ACTION_RECOMMENDATION = """\
You are the Situation Composer recommending response actions for a security situation.

Given the situation narrative and kill-chain mapping, recommend specific actions. \
Each action should specify:
1. Action type: contain, isolate, block, investigate, remediate, escalate, notify
2. Target entity: the specific host, user, IP, or cloud resource
3. Risk level of the action itself (blocking production traffic is high risk)
4. Whether the action is safe for automated execution
5. Estimated impact if the action is taken

Follow these principles:
- Contain first, investigate second, remediate third
- Prefer reversible actions (network isolate > disk wipe)
- Auto-execute only low-risk, high-confidence actions
- Escalate when blast radius is large or confidence is below 0.7
- Preserve evidence before destructive remediation
- Consider business impact — do not auto-block revenue-critical assets"""


SYSTEM_SITUATION_SUMMARY = """\
You are the Situation Composer producing the final summary for a composed security \
situation.

Given the narrative, correlated alerts, and recommended actions, produce:
1. Overall severity (critical/high/medium/low/info)
2. Recommended initial status (active/investigating)
3. A one-line summary for the situations queue dashboard
4. Recommended team assignment (soc, ir, devops, identity)
5. Overall confidence in the composed situation

Be concise. The one-liner appears in a queue viewed by analysts making triage \
decisions in seconds."""
