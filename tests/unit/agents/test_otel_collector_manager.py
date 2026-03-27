"""Tests for shieldops.agents.otel_collector_manager."""

from __future__ import annotations

from shieldops.agents.otel_collector_manager.models import (
    CollectorAction,
    DeploymentMode,
    OTelCollectorManagerState,
    PipelineType,
)


class TestEnums:
    def test_collectoraction_deploy(self):
        assert CollectorAction.DEPLOY == "deploy"

    def test_collectoraction_configure(self):
        assert CollectorAction.CONFIGURE == "configure"

    def test_collectoraction_scale(self):
        assert CollectorAction.SCALE == "scale"

    def test_collectoraction_health_check(self):
        assert CollectorAction.HEALTH_CHECK == "health_check"

    def test_pipelinetype_traces(self):
        assert PipelineType.TRACES == "traces"

    def test_pipelinetype_metrics(self):
        assert PipelineType.METRICS == "metrics"

    def test_pipelinetype_logs(self):
        assert PipelineType.LOGS == "logs"

    def test_deploymentmode_agent(self):
        assert DeploymentMode.AGENT == "agent"

    def test_deploymentmode_gateway(self):
        assert DeploymentMode.GATEWAY == "gateway"

    def test_deploymentmode_sidecar(self):
        assert DeploymentMode.SIDECAR == "sidecar"


class TestModels:
    def test_state_defaults(self):
        s = OTelCollectorManagerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.otel_collector_manager.graph import (
            create_otel_collector_manager_graph,
        )

        sg = create_otel_collector_manager_graph()
        assert sg.compile() is not None
