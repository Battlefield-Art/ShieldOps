"""Tests for the OTel Deployment Orchestrator agent."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from shieldops.agents.otel_deployer.models import (
    ClusterTarget,
    DeploymentPlan,
    DeploymentResult,
    DeployStage,
    K8sTarget,
    OTelDeployerState,
    RolloutStrategy,
)
from shieldops.agents.otel_deployer.nodes import (
    deploy_collectors,
    plan_deployments,
    validate_configs,
    verify_and_report,
)
from shieldops.agents.otel_deployer.prompts import (
    SYSTEM_DEPLOY,
    SYSTEM_PLAN,
    SYSTEM_VALIDATE,
    SYSTEM_VERIFY,
)
from shieldops.agents.otel_deployer.tools import OTelDeployerToolkit


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestDeployStage:
    def test_values(self) -> None:
        assert DeployStage.PLAN == "plan"
        assert DeployStage.VALIDATE == "validate"
        assert DeployStage.DEPLOY == "deploy"
        assert DeployStage.VERIFY == "verify"
        assert DeployStage.ROLLBACK == "rollback"

    def test_member_count(self) -> None:
        assert len(DeployStage) == 5


class TestClusterTarget:
    def test_values(self) -> None:
        assert ClusterTarget.DAEMONSET == "daemonset"
        assert ClusterTarget.DEPLOYMENT == "deployment"
        assert ClusterTarget.SIDECAR == "sidecar"

    def test_member_count(self) -> None:
        assert len(ClusterTarget) == 3


class TestRolloutStrategy:
    def test_values(self) -> None:
        assert RolloutStrategy.ROLLING == "rolling"
        assert RolloutStrategy.BLUE_GREEN == "blue_green"
        assert RolloutStrategy.CANARY == "canary"

    def test_member_count(self) -> None:
        assert len(RolloutStrategy) == 3


class TestK8sTarget:
    def test_defaults(self) -> None:
        target = K8sTarget()
        assert target.cluster_name == ""
        assert target.namespace == "default"
        assert target.node_count == 0
        assert target.labels == {}

    def test_custom_values(self) -> None:
        target = K8sTarget(
            cluster_name="prod-cluster",
            namespace="monitoring",
            node_count=10,
            labels={"env": "production"},
        )
        assert target.cluster_name == "prod-cluster"
        assert target.namespace == "monitoring"
        assert target.node_count == 10
        assert target.labels["env"] == "production"


class TestDeploymentPlan:
    def test_defaults(self) -> None:
        plan = DeploymentPlan()
        assert plan.strategy == RolloutStrategy.ROLLING
        assert plan.collector_image == "otel/opentelemetry-collector-contrib:latest"
        assert plan.replicas == 1
        assert plan.resource_limits == {}
        assert plan.config_yaml == ""

    def test_custom_plan(self) -> None:
        target = K8sTarget(cluster_name="staging", namespace="otel")
        plan = DeploymentPlan(
            target=target,
            strategy=RolloutStrategy.CANARY,
            replicas=3,
            config_yaml="receivers: {}",
        )
        assert plan.target.cluster_name == "staging"
        assert plan.strategy == RolloutStrategy.CANARY
        assert plan.replicas == 3


class TestDeploymentResult:
    def test_defaults(self) -> None:
        result = DeploymentResult()
        assert result.cluster_name == ""
        assert result.status == ""
        assert result.healthy_pods == 0
        assert result.total_pods == 0
        assert result.config_hash == ""

    def test_successful_result(self) -> None:
        result = DeploymentResult(
            cluster_name="prod",
            status="deployed",
            healthy_pods=5,
            total_pods=5,
            config_hash="abc123",
        )
        assert result.status == "deployed"
        assert result.healthy_pods == result.total_pods


class TestOTelDeployerState:
    def test_defaults(self) -> None:
        state = OTelDeployerState()
        assert state.request_id == ""
        assert state.stage == DeployStage.PLAN
        assert state.targets == []
        assert state.plans == []
        assert state.results == []
        assert state.rollback_available is False
        assert state.confidence_score == 0.0
        assert state.reasoning_chain == []
        assert state.error == ""


# ---------------------------------------------------------------------------
# Toolkit tests
# ---------------------------------------------------------------------------


class TestOTelDeployerToolkit:
    @pytest.mark.asyncio
    async def test_discover_clusters_no_client(self) -> None:
        toolkit = OTelDeployerToolkit()
        targets = await toolkit.discover_clusters()
        assert len(targets) == 2
        assert targets[0].cluster_name == "prod-us-east-1"
        assert targets[1].cluster_name == "staging-us-west-2"

    @pytest.mark.asyncio
    async def test_discover_clusters_with_filter(self) -> None:
        toolkit = OTelDeployerToolkit()
        targets = await toolkit.discover_clusters(namespace_filter="monitoring")
        assert all(t.namespace == "monitoring" for t in targets)

    def test_create_deployment_plan(self) -> None:
        toolkit = OTelDeployerToolkit()
        target = K8sTarget(cluster_name="test", namespace="ns", node_count=3)
        plan = toolkit.create_deployment_plan(
            target=target,
            config_yaml="receivers: {}",
            strategy=RolloutStrategy.CANARY,
        )
        assert plan.target.cluster_name == "test"
        assert plan.strategy == RolloutStrategy.CANARY
        assert plan.replicas == 3
        assert plan.resource_limits["cpu"] == "500m"
        assert plan.resource_limits["memory"] == "512Mi"

    def test_create_deployment_plan_large_cluster(self) -> None:
        toolkit = OTelDeployerToolkit()
        target = K8sTarget(cluster_name="big", namespace="ns", node_count=10)
        plan = toolkit.create_deployment_plan(target=target, config_yaml="x: y")
        assert plan.resource_limits["cpu"] == "1000m"
        assert plan.resource_limits["memory"] == "1Gi"

    @pytest.mark.asyncio
    async def test_apply_deployment_simulated(self) -> None:
        toolkit = OTelDeployerToolkit()
        target = K8sTarget(cluster_name="sim", namespace="default", node_count=2)
        plan = DeploymentPlan(target=target, config_yaml="receivers: {}", replicas=2)
        result = await toolkit.apply_deployment(plan)
        assert result.status == "simulated"
        assert result.healthy_pods == 2
        assert result.total_pods == 2
        assert result.config_hash != ""

    @pytest.mark.asyncio
    async def test_apply_deployment_dry_run(self) -> None:
        toolkit = OTelDeployerToolkit()
        target = K8sTarget(cluster_name="dry", namespace="default")
        plan = DeploymentPlan(target=target, config_yaml="x: y", replicas=1)
        result = await toolkit.apply_deployment(plan, dry_run=True)
        assert result.status == "dry_run"

    @pytest.mark.asyncio
    async def test_verify_deployment_no_client(self) -> None:
        toolkit = OTelDeployerToolkit()
        result = await toolkit.verify_deployment("cluster1", "default")
        assert result["healthy"] is True
        assert result["total_pods"] == 3
        assert result["zpages_reachable"] is True

    @pytest.mark.asyncio
    async def test_rollback_deployment_no_client(self) -> None:
        toolkit = OTelDeployerToolkit()
        result = await toolkit.rollback_deployment("cluster1", "default")
        assert result["status"] == "simulated_rollback"
        assert result["cluster_name"] == "cluster1"

    @pytest.mark.asyncio
    async def test_discover_clusters_with_k8s_client_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.list_namespaces.side_effect = RuntimeError("connection refused")
        toolkit = OTelDeployerToolkit(k8s_client=mock_client)
        targets = await toolkit.discover_clusters()
        assert len(targets) == 1
        assert targets[0].cluster_name == "error"


# ---------------------------------------------------------------------------
# Node tests
# ---------------------------------------------------------------------------


class TestPlanDeploymentsNode:
    @pytest.mark.asyncio
    async def test_plan_discovers_clusters(self) -> None:
        toolkit = OTelDeployerToolkit()
        state: dict = {"reasoning_chain": [], "targets": [], "plans": []}
        result = await plan_deployments(state, toolkit)
        assert result["stage"] == "plan"
        assert len(result["targets"]) == 2
        assert len(result["plans"]) == 2
        assert result["confidence_score"] == 0.7

    @pytest.mark.asyncio
    async def test_plan_uses_existing_targets(self) -> None:
        toolkit = OTelDeployerToolkit()
        target = K8sTarget(cluster_name="existing", namespace="ns", node_count=1)
        state: dict = {
            "reasoning_chain": [],
            "targets": [target.model_dump()],
            "plans": [],
        }
        result = await plan_deployments(state, toolkit)
        assert len(result["targets"]) == 1
        assert result["targets"][0]["cluster_name"] == "existing"


class TestValidateConfigsNode:
    @pytest.mark.asyncio
    async def test_validate_valid_plans(self) -> None:
        toolkit = OTelDeployerToolkit()
        target = K8sTarget(cluster_name="c1", namespace="ns")
        plan = DeploymentPlan(
            target=target,
            config_yaml="receivers: {}",
            resource_limits={"cpu": "500m", "memory": "512Mi"},
        )
        state: dict = {"reasoning_chain": [], "plans": [plan.model_dump()]}
        result = await validate_configs(state, toolkit)
        assert result["stage"] == "validate"
        assert result["confidence_score"] == 0.9

    @pytest.mark.asyncio
    async def test_validate_empty_config(self) -> None:
        toolkit = OTelDeployerToolkit()
        target = K8sTarget(cluster_name="c1", namespace="ns")
        plan = DeploymentPlan(
            target=target,
            config_yaml="",
            resource_limits={"cpu": "500m", "memory": "512Mi"},
        )
        state: dict = {"reasoning_chain": [], "plans": [plan.model_dump()]}
        result = await validate_configs(state, toolkit)
        assert result["confidence_score"] < 0.9


class TestDeployCollectorsNode:
    @pytest.mark.asyncio
    async def test_deploy_simulated(self) -> None:
        toolkit = OTelDeployerToolkit()
        target = K8sTarget(cluster_name="c1", namespace="ns", node_count=2)
        plan = DeploymentPlan(target=target, config_yaml="x: y", replicas=2)
        state: dict = {"reasoning_chain": [], "plans": [plan.model_dump()]}
        result = await deploy_collectors(state, toolkit)
        assert result["stage"] == "deploy"
        assert len(result["results"]) == 1
        assert result["rollback_available"] is True
        assert result["confidence_score"] == 0.95


class TestVerifyAndReportNode:
    @pytest.mark.asyncio
    async def test_verify_healthy(self) -> None:
        toolkit = OTelDeployerToolkit()
        target = K8sTarget(cluster_name="c1", namespace="ns")
        plan = DeploymentPlan(target=target, config_yaml="x: y")
        dr = DeploymentResult(cluster_name="c1", status="simulated")
        state: dict = {
            "reasoning_chain": [],
            "plans": [plan.model_dump()],
            "results": [dr.model_dump()],
        }
        result = await verify_and_report(state, toolkit)
        assert result["stage"] == "verify"
        assert result["confidence_score"] == 1.0
        assert any("all healthy" in r for r in result["reasoning_chain"])


# ---------------------------------------------------------------------------
# Prompt tests
# ---------------------------------------------------------------------------


class TestPrompts:
    def test_prompts_non_empty(self) -> None:
        assert len(SYSTEM_PLAN) > 50
        assert len(SYSTEM_VALIDATE) > 50
        assert len(SYSTEM_DEPLOY) > 50
        assert len(SYSTEM_VERIFY) > 50

    def test_plan_mentions_modes(self) -> None:
        assert "DaemonSet" in SYSTEM_PLAN
        assert "Deployment" in SYSTEM_PLAN
        assert "Sidecar" in SYSTEM_PLAN

    def test_verify_mentions_zpages(self) -> None:
        assert "zpages" in SYSTEM_VERIFY
