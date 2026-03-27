"""Tests for shieldops.agents.policy_engine."""

from __future__ import annotations

from shieldops.agents.policy_engine.models import (
    PolicyEngineState,
    PolicyStage,
    PolicyStatus,
    PolicyType,
)


class TestEnums:
    def test_policystage_collect_requirements(self):
        assert PolicyStage.COLLECT_REQUIREMENTS == "collect_requirements"

    def test_policystage_generate_policies(self):
        assert PolicyStage.GENERATE_POLICIES == "generate_policies"

    def test_policystage_validate_coverage(self):
        assert PolicyStage.VALIDATE_COVERAGE == "validate_coverage"

    def test_policystage_detect_drift(self):
        assert PolicyStage.DETECT_DRIFT == "detect_drift"

    def test_policytype_access_control(self):
        assert PolicyType.ACCESS_CONTROL == "access_control"

    def test_policytype_agent_behavior(self):
        assert PolicyType.AGENT_BEHAVIOR == "agent_behavior"

    def test_policytype_data_protection(self):
        assert PolicyType.DATA_PROTECTION == "data_protection"

    def test_policytype_network(self):
        assert PolicyType.NETWORK == "network"

    def test_policystatus_active(self):
        assert PolicyStatus.ACTIVE == "active"

    def test_policystatus_draft(self):
        assert PolicyStatus.DRAFT == "draft"

    def test_policystatus_deprecated(self):
        assert PolicyStatus.DEPRECATED == "deprecated"

    def test_policystatus_drifted(self):
        assert PolicyStatus.DRIFTED == "drifted"


class TestModels:
    def test_state_defaults(self):
        s = PolicyEngineState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.policy_engine.graph import (
            create_policy_engine_graph,
        )

        sg = create_policy_engine_graph()
        assert sg.compile() is not None
