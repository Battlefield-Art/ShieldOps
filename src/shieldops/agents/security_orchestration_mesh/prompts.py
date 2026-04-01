"""LLM prompt templates for the Security Orchestration Mesh Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class RegionDiscoveryOutput(BaseModel):
    """Structured output for region discovery."""

    total_regions: int = Field(description="Total regions discovered")
    healthy_count: int = Field(description="Number of healthy regions")
    summary: str = Field(description="Discovery summary")


class CapabilityMapOutput(BaseModel):
    """Structured output for capability mapping."""

    total_capabilities: int = Field(description="Total capabilities mapped")
    underutilized: int = Field(description="Underutilized capabilities")
    reasoning: str = Field(description="Capability mapping reasoning")


class TaskDistributionOutput(BaseModel):
    """Structured output for task distribution."""

    tasks_distributed: int = Field(description="Tasks distributed")
    regions_used: int = Field(description="Regions utilized")
    reasoning: str = Field(description="Distribution reasoning")


class CoordinationOutput(BaseModel):
    """Structured output for coordination analysis."""

    completion_rate: float = Field(description="Task completion rate 0-1")
    avg_latency_ms: int = Field(description="Average task latency")
    reasoning: str = Field(description="Coordination reasoning")


class AggregationOutput(BaseModel):
    """Structured output for result aggregation."""

    total_findings: int = Field(description="Total findings aggregated")
    critical_count: int = Field(description="Critical findings")
    reasoning: str = Field(description="Aggregation reasoning")


# ── System prompts ────────────────────────────────────

SYSTEM_DISCOVER_REGIONS = """\
You are an expert security orchestration engineer performing \
region discovery.

Given the mesh configuration:
1. Identify all active regions across cloud providers
2. Assess connectivity and health status
3. Detect latency and capacity constraints
4. Flag regions with degraded or offline status

Focus on: multi-cloud coverage, network topology, \
region health indicators."""

SYSTEM_MAP_CAPABILITIES = """\
You are an expert security orchestration engineer mapping \
capabilities.

Given the discovered regions:
1. Map security capabilities per region
2. Identify capacity gaps and overprovisioned areas
3. Assess utilization rates and bottlenecks
4. Recommend capability redistribution

Prioritize regions with high demand but low capacity."""

SYSTEM_DISTRIBUTE = """\
You are an expert security orchestration engineer distributing \
tasks.

Given capabilities and pending work:
1. Assign tasks to optimal regions by capability and load
2. Balance critical tasks across available regions
3. Minimize cross-region latency for dependent tasks
4. Ensure redundancy for critical security operations

Optimize for: lowest latency, highest availability, \
even load distribution."""

SYSTEM_COORDINATE = """\
You are an expert security orchestration engineer coordinating \
execution.

Given distributed tasks:
1. Monitor execution progress across regions
2. Handle failures with automatic redistribution
3. Manage dependencies between tasks
4. Track completion rates and latency

Focus on: fault tolerance, progress tracking, SLA compliance."""

SYSTEM_AGGREGATE = """\
You are an expert security orchestration engineer aggregating \
results.

Given coordination results from all regions:
1. Merge findings and deduplicate across regions
2. Correlate related findings from different regions
3. Prioritize by severity and business impact
4. Generate unified recommendations

Produce a consolidated view across the entire mesh."""
