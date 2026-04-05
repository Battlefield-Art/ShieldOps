"""LLM prompt templates for the Security Workflow Optimizer Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class WorkflowCollectionOutput(BaseModel):
    """Structured output for workflow collection."""

    total_workflows: int = Field(description="Total workflows collected")
    categories_found: int = Field(description="Distinct categories")
    summary: str = Field(description="Collection summary")


class PatternAnalysisOutput(BaseModel):
    """Structured output for pattern analysis."""

    total_patterns: int = Field(description="Total patterns identified")
    high_latency_count: int = Field(description="High-latency patterns")
    reasoning: str = Field(description="Pattern analysis reasoning")


class BottleneckOutput(BaseModel):
    """Structured output for bottleneck identification."""

    bottlenecks_found: int = Field(description="Bottlenecks identified")
    critical_count: int = Field(description="Critical bottlenecks")
    reasoning: str = Field(description="Bottleneck reasoning")


class OptimizationOutput(BaseModel):
    """Structured output for path optimization."""

    optimizations_applied: int = Field(description="Optimizations applied")
    avg_improvement_pct: float = Field(description="Average improvement %")
    reasoning: str = Field(description="Optimization reasoning")


class ValidationOutput(BaseModel):
    """Structured output for improvement validation."""

    tests_passed: int = Field(description="Validation tests passed")
    tests_failed: int = Field(description="Validation tests failed")
    reasoning: str = Field(description="Validation reasoning")


# ── System prompts ────────────────────────────────────

SYSTEM_COLLECT_WORKFLOWS = """\
You are an expert security workflow analyst collecting \
workflow data.

Given the configuration:
1. Inventory all security workflows in scope
2. Classify each by category and complexity
3. Gather execution history and performance metrics
4. Identify workflows with highest execution frequency

Focus on: incident response, threat detection, \
vulnerability management workflows."""

SYSTEM_ANALYZE_PATTERNS = """\
You are an expert security workflow analyst identifying \
execution patterns.

Given collected workflows:
1. Analyze execution frequency and timing patterns
2. Identify common failure modes and retry patterns
3. Detect latency spikes and performance anomalies
4. Correlate patterns across related workflows

Prioritize patterns that indicate systemic inefficiencies."""

SYSTEM_IDENTIFY_BOTTLENECKS = """\
You are an expert security workflow analyst identifying \
bottlenecks.

Given pattern analysis results:
1. Pinpoint steps causing the most delay
2. Identify resource contention points
3. Detect serial steps that could be parallelized
4. Assess impact of each bottleneck on overall throughput

Rank bottlenecks by business impact and ease of resolution."""

SYSTEM_OPTIMIZE_PATHS = """\
You are an expert security workflow optimizer applying \
improvements.

Given identified bottlenecks:
1. Design optimized execution paths
2. Apply parallelization where possible
3. Eliminate redundant steps
4. Recommend automation for manual steps

Optimize for: lowest latency, highest reliability, \
minimal resource usage."""

SYSTEM_VALIDATE = """\
You are an expert security workflow validator verifying \
improvements.

Given optimization results:
1. Compare before and after performance metrics
2. Verify no regression in workflow correctness
3. Validate that SLAs are still met
4. Identify any optimizations that need rollback

Ensure all improvements are safe for production."""
