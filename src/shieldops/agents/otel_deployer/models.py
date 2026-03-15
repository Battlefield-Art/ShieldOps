"""OTel Deployment Orchestrator Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class DeployStage(StrEnum):
    PLAN = "plan"
    VALIDATE = "validate"
    DEPLOY = "deploy"
    VERIFY = "verify"
    ROLLBACK = "rollback"


class ClusterTarget(StrEnum):
    DAEMONSET = "daemonset"
    DEPLOYMENT = "deployment"
    SIDECAR = "sidecar"


class RolloutStrategy(StrEnum):
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    CANARY = "canary"


class K8sTarget(BaseModel):
    """A Kubernetes cluster/namespace target for collector deployment."""

    cluster_name: str = ""
    namespace: str = "default"
    node_count: int = 0
    labels: dict[str, str] = Field(default_factory=dict)


class DeploymentPlan(BaseModel):
    """Plan for deploying an OTel Collector to a K8s target."""

    target: K8sTarget = Field(default_factory=K8sTarget)
    strategy: RolloutStrategy = RolloutStrategy.ROLLING
    collector_image: str = "otel/opentelemetry-collector-contrib:latest"
    replicas: int = 1
    resource_limits: dict[str, str] = Field(default_factory=dict)
    config_yaml: str = ""


class DeploymentResult(BaseModel):
    """Result of a collector deployment operation."""

    cluster_name: str = ""
    status: str = ""
    healthy_pods: int = 0
    total_pods: int = 0
    config_hash: str = ""


class OTelDeployerState(BaseModel):
    """Main state for the OTel Deployment Orchestrator agent graph."""

    request_id: str = ""
    stage: DeployStage = DeployStage.PLAN
    targets: list[K8sTarget] = Field(default_factory=list)
    plans: list[DeploymentPlan] = Field(default_factory=list)
    results: list[DeploymentResult] = Field(default_factory=list)
    rollback_available: bool = False
    confidence_score: float = 0.0
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
