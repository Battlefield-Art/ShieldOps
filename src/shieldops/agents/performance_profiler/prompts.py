"""Performance Profiler Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class BottleneckAnalysisResult(BaseModel):
    """Structured output from LLM-assisted bottleneck analysis."""

    summary: str = Field(description="Brief summary of performance bottleneck analysis")
    critical_bottlenecks: list[str] = Field(
        description="Critical bottlenecks requiring immediate attention"
    )
    root_causes: list[str] = Field(
        description="Root cause hypotheses for the detected performance issues"
    )
    optimization_priorities: list[str] = Field(
        description="Ranked optimization priorities with expected impact"
    )


class ReportSummaryResult(BaseModel):
    """Structured output from LLM-assisted report generation."""

    executive_summary: str = Field(
        description="Executive summary of the performance profiling session"
    )
    top_findings: list[str] = Field(description="Top findings ordered by business impact")
    action_items: list[str] = Field(description="Concrete action items for the engineering team")


SYSTEM_COLLECT = (
    "You are a performance engineer collecting distributed trace data.\n"
    "For the target tenant environment:\n"
    "1. Identify all service-to-service call paths and their latencies\n"
    "2. Capture span metadata including status codes, retries, and queue times\n"
    "3. Note any spans with error status codes or abnormal durations\n"
    "4. Map the critical path through the request lifecycle"
)

SYSTEM_ANALYZE_LATENCY = (
    "You are an APM analyst computing latency distributions.\n"
    "For each service endpoint:\n"
    "1. Calculate p50, p95, and p99 latency percentiles\n"
    "2. Identify endpoints with high tail latency (p99/p50 ratio > 5)\n"
    "3. Correlate error rates with latency spikes\n"
    "4. Estimate throughput impact of slow endpoints on overall SLA"
)

SYSTEM_DETECT_BOTTLENECKS = (
    "You are a performance bottleneck detective analyzing trace and latency data.\n"
    "For each detected bottleneck:\n"
    "1. Classify the bottleneck type: database, external API, CPU, memory, "
    "lock contention, or network I/O\n"
    "2. Determine the blast radius — how many upstream callers are affected\n"
    "3. Estimate the latency contribution as percentage of total request time\n"
    "4. Propose a concrete optimization with expected improvement percentage"
)

SYSTEM_IDENTIFY_CONTENTION = (
    "You are a systems engineer identifying resource contention.\n"
    "For each shared resource:\n"
    "1. Detect connection pool exhaustion, thread starvation, or lock waits\n"
    "2. Identify head-of-line blocking in single-threaded components\n"
    "3. Map contention to affected downstream operations\n"
    "4. Recommend capacity tuning or architectural changes to relieve contention"
)

SYSTEM_RECOMMEND = (
    "You are a performance optimization architect.\n"
    "Given bottlenecks and resource contention findings:\n"
    "1. Prioritize optimizations by estimated latency reduction * request volume\n"
    "2. Group related optimizations that should be deployed together\n"
    "3. Flag any optimizations that trade latency for throughput or vice versa\n"
    "4. Provide implementation guidance with estimated effort and risk level"
)

SYSTEM_REPORT = (
    "You are a performance engineering lead writing a profiling report.\n"
    "Produce an executive summary covering:\n"
    "1. Overall service health and SLA compliance\n"
    "2. Top 3 bottlenecks with business impact quantification\n"
    "3. Resource contention hotspots and capacity headroom\n"
    "4. Prioritized action items with expected improvement metrics"
)
