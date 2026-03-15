"""OTel Semantic Conventions Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ViolationAnalysisResult(BaseModel):
    """Structured output from LLM-assisted violation analysis."""

    summary: str = Field(description="Brief summary of violation analysis")
    common_patterns: list[str] = Field(
        description="Common violation patterns observed across services"
    )
    migration_needed: list[str] = Field(
        description="Deprecated conventions requiring migration"
    )
    priority_fixes: list[str] = Field(
        description="Highest priority fixes to address first"
    )


SYSTEM_LOAD_RULES = """You are an OpenTelemetry semantic conventions expert for ShieldOps.
Load and validate semantic convention rules for the requested scopes.

OTel Semantic Convention categories:
1. Resource attributes: service.name (required), service.version, deployment.environment,
   telemetry.sdk.name, telemetry.sdk.language, telemetry.sdk.version
2. Span attributes: http.request.method, url.path, url.scheme, server.address, server.port,
   rpc.system, db.system, messaging.system
3. Metric names: http.server.request.duration, http.client.request.duration,
   process.cpu.time, process.memory.usage
4. Log body: structured JSON with severity, body, resource context

Ensure all rules include expected patterns and descriptions.
"""

SYSTEM_SCAN_SERVICES = """You are scanning services for OTel semantic convention compliance.
For each service, check every telemetry attribute against loaded rules:

1. Extract all resource attributes, span names, metric names, and log fields
2. Match each against the expected naming convention pattern
3. Flag violations with appropriate severity:
   - ERROR: Missing required attributes (e.g. service.name) or completely wrong names
   - WARNING: Deprecated attribute names or non-standard patterns
   - INFO: Cosmetic issues or optional recommendations
4. Calculate a compliance score: compliant_count / total_attributes
"""

SYSTEM_ANALYZE_VIOLATIONS = """You are analyzing OTel semantic convention violations.
Group and prioritize violations across all scanned services:

1. Identify common violation patterns across multiple services
2. Rank by severity and frequency — widespread errors take priority
3. Check for deprecated OTel conventions that need migration
   (e.g. http.method -> http.request.method in semconv v1.20+)
4. Assess blast radius — how many traces/metrics are affected
5. Produce a prioritized remediation plan
"""

SYSTEM_GENERATE_FIXES = """You are generating fixes for OTel semantic convention violations.
For each violation, produce an actionable fix:

1. Attribute renames: OTel Collector transform processor config
   - Use transform processor with rename_attributes action
2. Missing attributes: Resource detection processor or SDK configuration
   - Configure resource/sdk detector or set OTEL_RESOURCE_ATTRIBUTES
3. Metric name changes: Views in the SDK or metric rename processor
4. Span naming: Instrumentation library configuration or span processor

Output both the processor YAML and the SDK-level configuration changes needed.
"""
