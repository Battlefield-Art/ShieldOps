"""LLM prompt templates and response schemas for the War Room Coordinator."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RoleAssignmentOutput(BaseModel):
    """Structured output for role assignment."""

    assignments: list[dict[str, str]] = Field(description="List of role-to-person mappings")
    reasoning: str = Field(description="Reasoning for assignments")


class ActionPlanOutput(BaseModel):
    """Structured output for action planning."""

    actions: list[dict[str, str]] = Field(description="Prioritized action items")
    critical_path: list[str] = Field(description="Critical path actions")


class CommsOutput(BaseModel):
    """Structured output for communication coordination."""

    update_message: str = Field(description="Status update message")
    audience: str = Field(description="Target audience for the update")
    urgency: str = Field(description="Urgency: critical/high/medium/low")
    channels: list[str] = Field(description="Recommended channels")


class ReportOutput(BaseModel):
    """Structured output for war room summary."""

    executive_summary: str = Field(description="One-paragraph executive summary")
    actions_completed: int = Field(description="Number of actions completed")
    key_decisions: list[str] = Field(description="Key decisions made in war room")
    open_items: list[str] = Field(description="Remaining open items")


SYSTEM_ASSIGN_ROLES = """\
You are an expert incident commander assigning \
war room roles.

Given the incident severity, type, and available \
personnel, assign:
1. Incident Commander — overall coordination
2. Technical Lead — hands-on investigation
3. Communications — stakeholder updates
4. Other roles as needed (legal, executive, forensics)

Consider expertise, availability, and conflict \
of interest."""


SYSTEM_TRACK_ACTIONS = """\
You are an expert incident coordinator tracking \
action items in a war room.

Given the current incident state and role \
assignments, generate:
1. Prioritized action items for each role
2. Critical path actions that block resolution
3. Dependencies between actions

Focus on immediate containment and investigation."""


SYSTEM_COORDINATE_COMMS = """\
You are an expert communications coordinator \
during an active incident.

Given the incident timeline and current status:
1. Draft appropriate status updates
2. Identify the right audience and channels
3. Set urgency level for each communication
4. Ensure consistent messaging

Keep updates factual, concise, and actionable."""


SYSTEM_REPORT = """\
You are an expert incident coordinator generating \
a war room summary report.

Given all actions, timeline, and communications:
1. Executive summary of the war room session
2. Actions completed vs outstanding
3. Key decisions made
4. Remaining open items

Be direct and focused on outcomes."""
