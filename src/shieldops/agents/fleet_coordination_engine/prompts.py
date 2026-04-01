"""LLM prompt templates and response schemas for Fleet Coordination Engine."""

from pydantic import BaseModel, Field

# ── Structured Output Schemas ───────────────────────────────


class AgentDiscoveryOutput(BaseModel):
    """LLM output for agent discovery."""

    agents_found: int = Field(
        description="Number of agents discovered",
    )
    roles_covered: int = Field(
        description="Number of unique roles in fleet",
    )
    summary: str = Field(
        description="Summary of fleet composition",
    )
    risk_level: str = Field(
        description="Fleet health: good/degraded/critical",
    )


class HealthAnalysisOutput(BaseModel):
    """LLM output for health analysis."""

    healthy_count: int = Field(
        description="Number of healthy agents",
    )
    degraded_count: int = Field(
        description="Number of degraded agents",
    )
    recommendations: list[str] = Field(
        description="Health improvement recommendations",
    )
    reasoning: str = Field(
        description="Health analysis reasoning",
    )


class RoutingPlanOutput(BaseModel):
    """LLM output for routing plan."""

    strategy: str = Field(
        description="Selected dispatch strategy",
    )
    assignments: list[dict[str, str]] = Field(
        description="Task-to-agent assignments",
    )
    load_score: float = Field(
        description="Load balance score 0-100",
    )
    reasoning: str = Field(
        description="Routing plan reasoning",
    )


class DispatchAnalysisOutput(BaseModel):
    """LLM output for dispatch analysis."""

    dispatched_count: int = Field(
        description="Number of tasks dispatched",
    )
    estimated_completion_ms: int = Field(
        description="Estimated total completion time",
    )
    bottlenecks: list[str] = Field(
        description="Identified bottlenecks",
    )
    reasoning: str = Field(
        description="Dispatch analysis reasoning",
    )


# ── System Prompts ──────────────────────────────────────────


SYSTEM_DISCOVER = """\
You are an expert fleet operations analyst discovering \
agents in a multi-agent security fleet.

Given the tenant configuration and fleet scope:
1. Enumerate all registered agents with their roles \
and capabilities
2. Identify agent clusters by role: investigators, \
responders, hunters, analysts, auditors, orchestrators
3. Detect orphaned or unregistered agents
4. Assess fleet composition against workload demands

Focus on ensuring coverage across all security domains."""


SYSTEM_HEALTH = """\
You are an expert fleet health analyst assessing the \
operational health of security agents.

Given discovered agents and their telemetry:
1. Evaluate CPU, memory, error rate, and latency metrics
2. Identify degraded or failing agents
3. Detect resource contention and memory leaks
4. Recommend scaling or replacement actions

Prioritize agents handling critical security workflows."""


SYSTEM_ROUTING = """\
You are an expert workload planner creating routing \
plans for multi-agent task distribution.

Given healthy agents and pending tasks:
1. Select optimal dispatch strategy based on workload
2. Match tasks to agents by capability and affinity
3. Balance load across the fleet to prevent hotspots
4. Estimate completion time per assignment

Optimize for both throughput and latency. Critical \
tasks must route to the most capable agents."""


SYSTEM_DISPATCH = """\
You are an expert fleet dispatcher analyzing task \
dispatch results for optimization.

Given dispatch results and agent assignments:
1. Verify all tasks were assigned to healthy agents
2. Identify dispatch failures and retry candidates
3. Detect bottlenecks in task processing
4. Recommend rebalancing if load becomes skewed

Ensure no critical tasks are dropped or delayed."""


SYSTEM_MONITOR = """\
You are an expert fleet monitor tracking progress \
of dispatched tasks across the agent fleet.

Given dispatch results and progress updates:
1. Track completion percentage per task and agent
2. Identify stalled or slow-running tasks
3. Recommend task reassignment for stuck items
4. Compute fleet utilization and throughput metrics

Escalate tasks exceeding SLA thresholds."""


SYSTEM_REPORT = """\
You are an expert fleet operations analyst generating \
a fleet coordination report.

Given the full coordination results:
1. Summarize fleet health and utilization
2. Report task dispatch and completion metrics
3. Highlight bottlenecks and optimization opportunities
4. Provide recommendations for fleet scaling

Keep the report actionable with clear priorities."""
