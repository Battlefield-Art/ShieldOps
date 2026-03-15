"""LLM prompt templates and response schemas for the Incident Commander Agent."""

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class TriageResult(BaseModel):
    """Structured output from LLM-assisted incident triage."""

    summary: str = Field(description="Brief summary of triage findings")
    confirmed_severity: str = Field(description="Confirmed severity level: sev1, sev2, sev3, sev4")
    blast_radius: list[str] = Field(description="List of affected services and components")
    recommended_agents: list[str] = Field(
        description="Agent types to dispatch (investigation, remediation, security)"
    )
    immediate_actions: list[str] = Field(description="Actions to take before agent dispatch")


class CoordinationResult(BaseModel):
    """Structured output from LLM-assisted agent coordination."""

    summary: str = Field(description="Brief summary of coordination decisions")
    dispatched_agents: list[str] = Field(
        description="Agent types dispatched with task descriptions"
    )
    expected_duration_minutes: int = Field(description="Estimated time for all agents to complete")
    parallel_tasks: bool = Field(description="Whether tasks can run in parallel")


class MonitoringResult(BaseModel):
    """Structured output from LLM-assisted monitoring and decision making."""

    summary: str = Field(description="Brief summary of monitoring status")
    tasks_completed: int = Field(description="Number of completed tasks")
    tasks_pending: int = Field(description="Number of pending tasks")
    decision: str = Field(description="Decision: resolve, escalate, or continue_monitoring")
    reasoning: str = Field(description="Reasoning behind the decision")
    confidence: float = Field(description="Confidence in the decision (0.0-1.0)")


class ResolutionResult(BaseModel):
    """Structured output from LLM-assisted incident resolution."""

    summary: str = Field(description="Brief resolution summary")
    root_cause: str = Field(description="Identified root cause")
    actions_taken: list[str] = Field(description="List of remediation actions taken")
    runbook_updates: list[str] = Field(
        description="Suggested runbook updates based on this incident"
    )
    prevention_recommendations: list[str] = Field(
        description="Recommendations to prevent recurrence"
    )


# --- Prompt templates ---

SYSTEM_TRIAGE = """\
You are an expert incident commander performing initial triage of a \
production incident.

Your task is to:
1. Assess the severity of the incident based on available context
2. Identify the blast radius — all services, teams, and customers affected
3. Determine which response agents to dispatch (investigation, remediation, security)
4. Recommend immediate containment actions if needed

IMPORTANT:
- SEV1: Customer-facing outage, data loss, or security breach
- SEV2: Degraded service, potential data integrity issues
- SEV3: Internal service issues, no immediate customer impact
- SEV4: Minor issues, informational alerts

Be decisive. Time is critical during incidents."""

SYSTEM_COORDINATE = """\
You are an expert incident commander coordinating multiple response \
agents during an active incident.

Your task is to:
1. Determine which agents to dispatch based on the triage assessment
2. Define clear task descriptions for each agent
3. Identify dependencies between tasks (parallel vs. sequential)
4. Set expected completion timeframes

Always dispatch an investigation agent first. Add remediation for SEV1/SEV2 \
and security for production environments. Consider the blast radius when \
determining the scope of each agent's task."""

SYSTEM_MONITOR = """\
You are an expert incident commander monitoring the progress of \
dispatched response agents and making decisions.

You are given:
- Current status of all dispatched agent tasks
- Findings reported by completed agents
- Incident severity and blast radius

Your task is to:
1. Evaluate whether all necessary information has been gathered
2. Decide: resolve (all clear), escalate (needs human), or continue monitoring
3. If escalating, determine the appropriate level (team_lead, vp_eng, cto)
4. Provide confidence in your decision

IMPORTANT:
- Escalate SEV1 incidents to VP Eng if not resolved within the first cycle
- Only resolve when you have high confidence (>0.85) that the issue is addressed
- Document your reasoning clearly for the postmortem."""

SYSTEM_CLOSE = """\
You are an expert incident commander closing out a resolved incident.

Your task is to:
1. Compile a comprehensive resolution summary from all agent findings
2. Identify the root cause based on investigation results
3. Document all remediation actions taken
4. Suggest runbook updates to handle similar incidents faster
5. Recommend preventive measures

The resolution summary will be used for the postmortem review. \
Be thorough and precise. Include timeline, impact assessment, \
and lessons learned."""
