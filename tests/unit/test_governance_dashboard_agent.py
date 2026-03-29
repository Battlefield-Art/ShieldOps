"""Unit tests for governance_dashboard agent."""

from __future__ import annotations

import pytest

from shieldops.agents.governance_dashboard.models import (
    GovernanceDashboardState,
    GovernanceMetric,
    GovernanceStage,
    PolicyAssessment,
    PolicyDomain,
    RiskPosture,
    RiskScore,
)
from shieldops.agents.governance_dashboard.tools import (
    DOMAIN_METRICS,
    GovernanceDashboardToolkit,
)

# -------------------------------------------------------------------
# Enums
# -------------------------------------------------------------------


class TestEnums:
    def test_governance_stage_values(self):
        assert GovernanceStage.COLLECT_METRICS == "collect_metrics"
        assert GovernanceStage.ASSESS_POLICIES == "assess_policies"
        assert GovernanceStage.SCORE_RISK == "score_risk"
        assert GovernanceStage.GENERATE_INSIGHTS == "generate_insights"
        assert GovernanceStage.EXECUTIVE_SUMMARY == "executive_summary"
        assert GovernanceStage.REPORT == "report"

    def test_policy_domain_values(self):
        assert PolicyDomain.ACCESS_CONTROL == "access_control"
        assert PolicyDomain.DATA_PROTECTION == "data_protection"
        assert PolicyDomain.INCIDENT_RESPONSE == "incident_response"
        assert PolicyDomain.CHANGE_MANAGEMENT == "change_management"
        assert PolicyDomain.VENDOR_RISK == "vendor_risk"
        assert PolicyDomain.BUSINESS_CONTINUITY == "business_continuity"

    def test_risk_posture_values(self):
        assert RiskPosture.STRONG == "strong"
        assert RiskPosture.ADEQUATE == "adequate"
        assert RiskPosture.NEEDS_IMPROVEMENT == "needs_improvement"
        assert RiskPosture.WEAK == "weak"
        assert RiskPosture.CRITICAL == "critical"


# -------------------------------------------------------------------
# State
# -------------------------------------------------------------------


class TestState:
    def test_defaults(self):
        state = GovernanceDashboardState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.error == ""
        assert state.stage == GovernanceStage.COLLECT_METRICS
        assert state.metrics == []
        assert state.policy_assessments == []
        assert state.risk_scores == []
        assert state.overall_posture == RiskPosture.ADEQUATE
        assert state.insights == []
        assert state.executive_summary == ""
        assert state.reasoning_chain == []
        assert state.session_start == 0.0

    def test_with_values(self):
        state = GovernanceDashboardState(
            request_id="req-1",
            tenant_id="t-1",
            overall_posture=RiskPosture.STRONG,
        )
        assert state.request_id == "req-1"
        assert state.overall_posture == RiskPosture.STRONG


# -------------------------------------------------------------------
# Models
# -------------------------------------------------------------------


class TestModels:
    def test_governance_metric_defaults(self):
        m = GovernanceMetric()
        assert m.id == ""
        assert m.name == ""
        assert m.domain == PolicyDomain.ACCESS_CONTROL
        assert m.value == 0.0
        assert m.target == 100.0
        assert m.unit == "%"

    def test_policy_assessment_defaults(self):
        pa = PolicyAssessment()
        assert pa.adherence_pct == 0.0
        assert pa.controls_total == 0
        assert pa.gaps == []
        assert pa.frameworks == []

    def test_risk_score_defaults(self):
        rs = RiskScore()
        assert rs.score == 0.0
        assert rs.posture == RiskPosture.ADEQUATE
        assert rs.factors == []
        assert rs.trend == "stable"


# -------------------------------------------------------------------
# Toolkit
# -------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        return GovernanceDashboardToolkit()

    @pytest.mark.asyncio()
    async def test_collect_metrics(self, toolkit):
        metrics = await toolkit.collect_metrics(
            tenant_id="t-test",
        )
        expected_count = sum(len(v) for v in DOMAIN_METRICS.values())
        assert len(metrics) == expected_count
        for m in metrics:
            assert isinstance(m, GovernanceMetric)
            assert m.id.startswith("gm-")
            assert m.collected_at > 0

    @pytest.mark.asyncio()
    async def test_assess_policies(self, toolkit):
        metrics = await toolkit.collect_metrics(
            tenant_id="t-test",
        )
        assessments = await toolkit.assess_policies(
            metrics=metrics,
        )
        assert len(assessments) == len(PolicyDomain)
        for a in assessments:
            assert isinstance(a, PolicyAssessment)
            assert a.id.startswith("pa-")
            assert a.controls_total > 0

    @pytest.mark.asyncio()
    async def test_score_risk(self, toolkit):
        metrics = await toolkit.collect_metrics(
            tenant_id="t-test",
        )
        assessments = await toolkit.assess_policies(
            metrics=metrics,
        )
        scores = await toolkit.score_risk(
            assessments=assessments,
            metrics=metrics,
        )
        assert len(scores) == len(assessments)
        for s in scores:
            assert isinstance(s, RiskScore)
            assert s.id.startswith("rs-")
            assert 0.0 <= s.score <= 100.0

    @pytest.mark.asyncio()
    async def test_compute_overall_posture(self, toolkit):
        scores = [
            RiskScore(score=95.0, posture=RiskPosture.STRONG),
            RiskScore(score=80.0, posture=RiskPosture.ADEQUATE),
        ]
        result = await toolkit.compute_overall_posture(scores)
        assert result == RiskPosture.ADEQUATE

    @pytest.mark.asyncio()
    async def test_compute_overall_posture_empty(self, toolkit):
        result = await toolkit.compute_overall_posture([])
        assert result == RiskPosture.ADEQUATE

    @pytest.mark.asyncio()
    async def test_build_executive_summary(self, toolkit):
        metrics = await toolkit.collect_metrics(
            tenant_id="t-test",
        )
        assessments = await toolkit.assess_policies(
            metrics=metrics,
        )
        scores = await toolkit.score_risk(
            assessments=assessments,
            metrics=metrics,
        )
        posture = await toolkit.compute_overall_posture(scores)
        summary = await toolkit.build_executive_summary(
            metrics=metrics,
            assessments=assessments,
            risk_scores=scores,
            overall_posture=posture,
            insights=["test insight"],
        )
        assert isinstance(summary, str)
        assert len(summary) > 0
        assert "Governance Posture" in summary


# -------------------------------------------------------------------
# Nodes
# -------------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio()
    async def test_collect_metrics_node(self):
        from shieldops.agents.governance_dashboard.nodes import (
            collect_metrics,
            set_toolkit,
        )

        set_toolkit(GovernanceDashboardToolkit())
        state = {
            "tenant_id": "t-1",
            "reasoning_chain": [],
        }
        result = await collect_metrics(state)
        assert "metrics" in result
        assert len(result["metrics"]) > 0
        assert result["stage"] == GovernanceStage.COLLECT_METRICS

    @pytest.mark.asyncio()
    async def test_assess_policies_node(self):
        from shieldops.agents.governance_dashboard.nodes import (
            assess_policies,
            set_toolkit,
        )

        set_toolkit(GovernanceDashboardToolkit())
        tk = GovernanceDashboardToolkit()
        metrics = await tk.collect_metrics("t-1")
        state = {
            "metrics": metrics,
            "reasoning_chain": [],
        }
        result = await assess_policies(state)
        assert "policy_assessments" in result
        assert len(result["policy_assessments"]) > 0

    @pytest.mark.asyncio()
    async def test_score_risk_node(self):
        from shieldops.agents.governance_dashboard.nodes import (
            score_risk,
            set_toolkit,
        )

        set_toolkit(GovernanceDashboardToolkit())
        tk = GovernanceDashboardToolkit()
        metrics = await tk.collect_metrics("t-1")
        assessments = await tk.assess_policies(metrics)
        state = {
            "policy_assessments": assessments,
            "metrics": metrics,
            "reasoning_chain": [],
        }
        result = await score_risk(state)
        assert "risk_scores" in result
        assert "overall_posture" in result

    @pytest.mark.asyncio()
    async def test_generate_insights_node(self):
        from shieldops.agents.governance_dashboard.nodes import (
            generate_insights,
            set_toolkit,
        )

        set_toolkit(GovernanceDashboardToolkit())
        tk = GovernanceDashboardToolkit()
        metrics = await tk.collect_metrics("t-1")
        assessments = await tk.assess_policies(metrics)
        scores = await tk.score_risk(assessments, metrics)
        state = {
            "metrics": metrics,
            "policy_assessments": assessments,
            "risk_scores": scores,
            "reasoning_chain": [],
        }
        result = await generate_insights(state)
        assert "insights" in result
        assert len(result["insights"]) > 0

    @pytest.mark.asyncio()
    async def test_report_node(self):
        from shieldops.agents.governance_dashboard.nodes import (
            report,
            set_toolkit,
        )

        set_toolkit(GovernanceDashboardToolkit())
        state = {
            "metrics": [],
            "policy_assessments": [],
            "risk_scores": [],
            "insights": [],
            "overall_posture": RiskPosture.ADEQUATE,
            "executive_summary": "Test summary",
            "reasoning_chain": [],
            "session_start": 0.0,
        }
        result = await report(state)
        assert result["stage"] == GovernanceStage.REPORT
        assert "stats" in result


# -------------------------------------------------------------------
# Graph
# -------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.governance_dashboard.graph import (
            create_governance_dashboard_graph,
        )

        sg = create_governance_dashboard_graph()
        compiled = sg.compile()
        assert compiled is not None


# -------------------------------------------------------------------
# Runner
# -------------------------------------------------------------------


class TestRunner:
    def test_runner_init(self):
        from shieldops.agents.governance_dashboard.runner import (
            GovernanceDashboardRunner,
        )

        runner = GovernanceDashboardRunner()
        assert runner is not None
