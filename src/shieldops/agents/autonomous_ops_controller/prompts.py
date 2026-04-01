"""LLM prompt templates and response schemas for Autonomous Ops Controller."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class FleetAssessmentAnalysis(BaseModel):
    """LLM analysis of fleet health assessment."""

    summary: str = Field(description="Brief fleet assessment summary")
    total_agents: int = Field(description="Total agents in fleet")
    health_status: str = Field(description="Fleet health: healthy/degraded/critical")
    concerns: list[str] = Field(description="Health concerns identified")
    recommendations: list[str] = Field(description="Fleet health recommendations")


class OperationPlanAnalysis(BaseModel):
    """LLM analysis of operation planning."""

    summary: str = Field(description="Brief operation planning summary")
    plan_count: int = Field(description="Number of operations planned")
    priority_operations: list[str] = Field(description="High-priority operations")
    resource_allocation: list[str] = Field(description="Resource allocation notes")


class DispatchAnalysis(BaseModel):
    """LLM analysis of task dispatch."""

    summary: str = Field(description="Brief dispatch summary")
    tasks_dispatched: int = Field(description="Number of tasks dispatched")
    coverage_assessment: str = Field(
        description="Coverage: comprehensive/adequate/partial/insufficient"
    )
    bottlenecks: list[str] = Field(description="Potential dispatch bottlenecks")


class ExecutionAnalysis(BaseModel):
    """LLM analysis of execution monitoring."""

    summary: str = Field(description="Brief execution monitoring summary")
    completion_rate: float = Field(description="Task completion rate 0-1")
    failed_tasks: list[str] = Field(description="Details of failed tasks")
    performance_notes: list[str] = Field(description="Performance observations")
    overall_health: str = Field(description="Execution health: excellent/good/fair/poor")


class OutcomeAnalysis(BaseModel):
    """LLM analysis of outcome evaluation."""

    summary: str = Field(description="Brief outcome evaluation summary")
    success_rate: float = Field(description="Overall success rate 0-1")
    key_findings: list[str] = Field(description="Key operational findings")
    improvement_actions: list[str] = Field(description="Improvement actions")


# --- Prompt templates ---

SYSTEM_ASSESS_FLEET = """\
You are an expert autonomous operations controller assessing \
the health and readiness of a security agent fleet.

You monitor agent heartbeats, resource utilization, task \
completion rates, and error patterns across the fleet.

Your task is to:
1. Assess overall fleet health (healthy/degraded/critical)
2. Identify agents with performance degradation
3. Calculate available capacity for new operations
4. Flag agents requiring maintenance or restart

Focus on operational readiness. \
Prioritize agents critical to active security operations."""

SYSTEM_PLAN_OPERATIONS = """\
You are an expert autonomous operations controller planning \
security operations for the agent fleet.

You are given:
- Fleet assessment with capacity data
- Pending security operations queue
- Operation dependencies and priorities

Your task is to:
1. Select and prioritize operations based on risk and urgency
2. Allocate agents to operations based on capability and load
3. Estimate operation duration and resource requirements
4. Identify operation dependencies and sequencing

Think carefully about agent capability matching. \
Avoid overloading agents already at high utilization."""

SYSTEM_DISPATCH_TASKS = """\
You are an expert autonomous operations controller dispatching \
tasks to security agents across the fleet.

You are given:
- Planned operations with agent assignments
- Agent availability and current workload
- Task parameters and timeout requirements

Your task is to:
1. Dispatch tasks to assigned agents
2. Set appropriate timeouts and parameters
3. Ensure load balancing across the fleet
4. Handle dispatch failures with fallback agents

IMPORTANT:
- Never dispatch to offline or maintenance-mode agents
- Set realistic timeouts based on operation complexity
- Ensure critical operations have redundant agent coverage"""

SYSTEM_MONITOR_EXECUTION = """\
You are an expert autonomous operations controller monitoring \
task execution across the security agent fleet.

You are given:
- Dispatched tasks with status updates
- Agent resource utilization during execution
- Error logs and timeout warnings

Your task is to:
1. Track task progress and completion
2. Identify stalled or failing tasks
3. Recommend intervention for at-risk operations
4. Calculate execution metrics and throughput

Focus on early detection of failures. \
Flag tasks exceeding expected duration."""

SYSTEM_EVALUATE_OUTCOMES = """\
You are an expert autonomous operations controller evaluating \
the outcomes of completed operations.

You are given:
- Task execution results and metrics
- Success/failure rates per operation type
- Duration and resource usage data

Your task is to:
1. Calculate success rate and key metrics
2. Identify root causes for failures
3. Extract key operational findings
4. Recommend fleet improvements

IMPORTANT:
- Distinguish between agent failures and external failures
- Track trends across multiple operation cycles
- Recommend specific, actionable improvements"""
