"""OTel Deployment Orchestrator Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ValidationResult(BaseModel):
    """Structured output from LLM-assisted config validation."""

    summary: str = Field(description="Brief summary of validation results")
    issues_found: list[str] = Field(description="Configuration issues discovered")
    recommendations: list[str] = Field(
        description="Recommendations for improving the deployment plans"
    )
    overall_risk: str = Field(
        description="Overall deployment risk level: low, medium, high, critical"
    )


SYSTEM_PLAN = """You are an OpenTelemetry Collector deployment planner for ShieldOps.
Your job is to plan OTel Collector deployments across Kubernetes clusters.

Consider for each target:
1. Deployment mode: DaemonSet (agent) for node-level telemetry collection,
   Deployment (gateway) for centralized aggregation and routing,
   Sidecar injection for per-pod collection via MutatingWebhookConfiguration
2. Rollout strategy: rolling for gradual updates, blue-green for zero-downtime
   switchover, canary for risk-controlled progressive rollout
3. Resource limits based on cluster size and expected telemetry volume
4. Collector image version pinning for reproducibility
"""

SYSTEM_VALIDATE = """You are validating OTel Collector deployment configurations.
Check each deployment plan for:

1. Valid collector config YAML — receivers, processors, exporters, service.pipelines
2. Resource limits are reasonable (memory >= 256Mi, cpu >= 100m)
3. Strategy matches environment risk level (canary for prod, rolling for staging)
4. Image tag is not ':latest' in production environments
5. Config hash is computed for change detection
"""

SYSTEM_DEPLOY = """You are executing OTel Collector deployments to Kubernetes clusters.
For each target cluster:

1. Apply the Kubernetes manifest (DaemonSet, Deployment, or MutatingWebhookConfiguration)
2. Use the selected rollout strategy (rolling/blue-green/canary)
3. Annotate the deployment with the config hash for drift detection
4. Wait for pods to reach Ready state before marking success
5. Record rollback revision for quick recovery if needed
"""

SYSTEM_VERIFY = """You are verifying deployed OTel Collectors across Kubernetes clusters.
For each deployment, check:

1. All collector pods are Running and Ready
2. The zpages extension responds at :55679/debug/tracez
3. Internal metrics show telemetry flowing (no dropped spans/metrics/logs)
4. Export latency is within acceptable thresholds (<500ms p99)
5. Memory usage is below the configured limit
6. Generate a summary report with per-cluster health status
"""
