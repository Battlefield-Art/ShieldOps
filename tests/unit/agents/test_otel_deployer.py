"""Tests for shieldops.agents.otel_deployer."""

from __future__ import annotations

from shieldops.agents.otel_deployer.models import (
    ClusterTarget,
    DeployStage,
    OTelDeployerState,
    RolloutStrategy,
)


class TestEnums:
    def test_deploystage_plan(self):
        assert DeployStage.PLAN == "plan"

    def test_deploystage_validate(self):
        assert DeployStage.VALIDATE == "validate"

    def test_deploystage_deploy(self):
        assert DeployStage.DEPLOY == "deploy"

    def test_deploystage_verify(self):
        assert DeployStage.VERIFY == "verify"

    def test_clustertarget_daemonset(self):
        assert ClusterTarget.DAEMONSET == "daemonset"

    def test_clustertarget_deployment(self):
        assert ClusterTarget.DEPLOYMENT == "deployment"

    def test_clustertarget_sidecar(self):
        assert ClusterTarget.SIDECAR == "sidecar"

    def test_rolloutstrategy_rolling(self):
        assert RolloutStrategy.ROLLING == "rolling"

    def test_rolloutstrategy_blue_green(self):
        assert RolloutStrategy.BLUE_GREEN == "blue_green"

    def test_rolloutstrategy_canary(self):
        assert RolloutStrategy.CANARY == "canary"


class TestModels:
    def test_state_defaults(self):
        s = OTelDeployerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.otel_deployer.graph import (
            create_otel_deployer_graph,
        )

        sg = create_otel_deployer_graph()
        assert sg.compile() is not None
