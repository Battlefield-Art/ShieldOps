"""Unit tests for security_awareness agent."""

from __future__ import annotations

import pytest

from shieldops.agents.security_awareness.models import (
    AwarenessStage,
    DepartmentSummary,
    PhishingResult,
    RiskTier,
    SecurityAwarenessState,
    SimulationType,
    TrainingRecord,
    UserRiskScore,
)
from shieldops.agents.security_awareness.tools import (
    SAMPLE_DEPARTMENTS,
    SIMULATION_TEMPLATES,
    SecurityAwarenessToolkit,
)

# -------------------------------------------------------------------
# Enums
# -------------------------------------------------------------------


class TestEnums:
    def test_awareness_stage_values(self):
        assert AwarenessStage.ASSESS_BASELINE == "assess_baseline"
        assert AwarenessStage.REPORT == "report"

    def test_simulation_type_values(self):
        assert SimulationType.PHISHING_EMAIL == "phishing_email"
        assert SimulationType.PRETEXTING == "pretexting"

    def test_risk_tier_values(self):
        assert RiskTier.CRITICAL == "critical"
        assert RiskTier.MINIMAL == "minimal"


# -------------------------------------------------------------------
# State
# -------------------------------------------------------------------


class TestState:
    def test_defaults(self):
        state = SecurityAwarenessState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.error == ""
        assert state.stage == AwarenessStage.ASSESS_BASELINE
        assert state.simulation_type == SimulationType.PHISHING_EMAIL
        assert state.phishing_results == []
        assert state.training_records == []
        assert state.risk_scores == []
        assert state.department_summaries == []
        assert state.overall_score == 0.0
        assert state.recommendations == []
        assert state.report_summary == ""
        assert state.reasoning_chain == []
        assert state.session_start == 0.0
        assert state.duration_ms == 0

    def test_with_values(self):
        state = SecurityAwarenessState(
            request_id="req-1",
            tenant_id="t-1",
            simulation_type=SimulationType.VISHING,
            overall_score=72.5,
        )
        assert state.simulation_type == SimulationType.VISHING
        assert state.overall_score == 72.5


# -------------------------------------------------------------------
# Models
# -------------------------------------------------------------------


class TestModels:
    def test_phishing_result_defaults(self):
        pr = PhishingResult()
        assert pr.user_id == ""
        assert pr.clicked_link is False
        assert pr.reported_phish is False
        assert pr.simulation_type == SimulationType.PHISHING_EMAIL

    def test_training_record_defaults(self):
        tr = TrainingRecord()
        assert tr.course_name == ""
        assert tr.score_pct == 0.0
        assert tr.passed is False
        assert tr.overdue is False

    def test_user_risk_score_defaults(self):
        rs = UserRiskScore()
        assert rs.risk_score == 0.0
        assert rs.risk_tier == RiskTier.MEDIUM
        assert rs.factors == []

    def test_department_summary_defaults(self):
        ds = DepartmentSummary()
        assert ds.department == ""
        assert ds.user_count == 0
        assert ds.avg_risk_score == 0.0


# -------------------------------------------------------------------
# Toolkit
# -------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        return SecurityAwarenessToolkit()

    @pytest.mark.asyncio()
    async def test_assess_baseline(self, toolkit):
        phishing, training = await toolkit.assess_baseline("tenant-1")
        assert len(phishing) > 0
        assert len(training) > 0
        assert all(isinstance(p, PhishingResult) for p in phishing)
        assert all(isinstance(t, TrainingRecord) for t in training)
        depts = {p.department for p in phishing}
        for d in SAMPLE_DEPARTMENTS:
            assert d in depts

    @pytest.mark.asyncio()
    async def test_run_simulations_phishing(self, toolkit):
        initial: list[PhishingResult] = []
        result = await toolkit.run_simulations(
            SimulationType.PHISHING_EMAIL,
            initial,
        )
        assert len(result) > 0
        templates = SIMULATION_TEMPLATES["phishing_email"]
        expected = len(SAMPLE_DEPARTMENTS) * len(templates)
        assert len(result) == expected

    @pytest.mark.asyncio()
    async def test_run_simulations_appends(self, toolkit):
        existing = [PhishingResult(id="existing-1", user_id="u1")]
        result = await toolkit.run_simulations(
            SimulationType.PHISHING_EMAIL,
            existing,
        )
        assert len(result) > len(existing)
        assert result[0].id == "existing-1"

    @pytest.mark.asyncio()
    async def test_track_training(self, toolkit):
        records = [
            TrainingRecord(user_id="u1", passed=True, assigned_at=1000),
            TrainingRecord(user_id="u2", passed=False, assigned_at=1000),
        ]
        updated = await toolkit.track_training(records)
        assert len(updated) == 2
        assert updated[1].overdue is True

    @pytest.mark.asyncio()
    async def test_score_risk(self, toolkit):
        phishing = [
            PhishingResult(
                user_id="u1",
                department="engineering",
                clicked_link=True,
            ),
            PhishingResult(
                user_id="u1",
                department="engineering",
                clicked_link=False,
            ),
            PhishingResult(
                user_id="u2",
                department="finance",
                clicked_link=True,
            ),
        ]
        training = [
            TrainingRecord(
                user_id="u1",
                department="engineering",
                passed=True,
                score_pct=90.0,
            ),
            TrainingRecord(
                user_id="u2",
                department="finance",
                passed=False,
                score_pct=0.0,
            ),
        ]
        scores, summaries = await toolkit.score_risk(phishing, training)
        assert len(scores) == 2
        assert len(summaries) == 2
        assert all(isinstance(s, UserRiskScore) for s in scores)
        assert all(isinstance(d, DepartmentSummary) for d in summaries)
        u2_score = next(s for s in scores if s.user_id == "u2")
        u1_score = next(s for s in scores if s.user_id == "u1")
        assert u2_score.risk_score > u1_score.risk_score

    @pytest.mark.asyncio()
    async def test_score_risk_empty(self, toolkit):
        scores, summaries = await toolkit.score_risk([], [])
        assert scores == []
        assert summaries == []

    @pytest.mark.asyncio()
    async def test_generate_recommendations(self, toolkit):
        risk_scores = [
            UserRiskScore(
                user_id="u1",
                department="finance",
                risk_tier=RiskTier.HIGH,
                risk_score=70.0,
            ),
        ]
        dept_summaries = [
            DepartmentSummary(
                department="finance",
                phishing_fail_rate=55.0,
                training_completion_pct=60.0,
            ),
        ]
        recs = await toolkit.generate_recommendations(
            risk_scores,
            dept_summaries,
        )
        assert len(recs) > 0

    @pytest.mark.asyncio()
    async def test_generate_recommendations_empty(self, toolkit):
        recs = await toolkit.generate_recommendations([], [])
        assert len(recs) == 1
        assert "Maintain" in recs[0]

    def test_classify_risk(self, toolkit):
        assert toolkit._classify_risk(85) == RiskTier.CRITICAL
        assert toolkit._classify_risk(65) == RiskTier.HIGH
        assert toolkit._classify_risk(45) == RiskTier.MEDIUM
        assert toolkit._classify_risk(25) == RiskTier.LOW
        assert toolkit._classify_risk(10) == RiskTier.MINIMAL


# -------------------------------------------------------------------
# Nodes
# -------------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio()
    async def test_assess_baseline_node(self):
        from shieldops.agents.security_awareness.nodes import (
            assess_baseline,
            set_toolkit,
        )

        set_toolkit(SecurityAwarenessToolkit())
        state = SecurityAwarenessState(tenant_id="t-1")
        result = await assess_baseline(state)
        assert "phishing_results" in result
        assert "training_records" in result
        assert result["stage"] == AwarenessStage.ASSESS_BASELINE

    @pytest.mark.asyncio()
    async def test_run_simulations_node(self):
        from shieldops.agents.security_awareness.nodes import (
            run_simulations,
            set_toolkit,
        )

        set_toolkit(SecurityAwarenessToolkit())
        state = SecurityAwarenessState(
            simulation_type=SimulationType.PHISHING_EMAIL,
            phishing_results=[],
        )
        result = await run_simulations(state)
        assert "phishing_results" in result
        assert len(result["phishing_results"]) > 0

    @pytest.mark.asyncio()
    async def test_track_training_node(self):
        from shieldops.agents.security_awareness.nodes import (
            set_toolkit,
            track_training,
        )

        set_toolkit(SecurityAwarenessToolkit())
        state = SecurityAwarenessState(
            training_records=[
                TrainingRecord(user_id="u1", passed=True, assigned_at=1000),
            ],
        )
        result = await track_training(state)
        assert "training_records" in result

    @pytest.mark.asyncio()
    async def test_score_risk_node(self):
        from shieldops.agents.security_awareness.nodes import (
            score_risk,
            set_toolkit,
        )

        set_toolkit(SecurityAwarenessToolkit())
        state = SecurityAwarenessState(
            phishing_results=[
                PhishingResult(
                    user_id="u1",
                    department="eng",
                    clicked_link=True,
                ),
            ],
            training_records=[
                TrainingRecord(
                    user_id="u1",
                    department="eng",
                    passed=True,
                    score_pct=80.0,
                ),
            ],
        )
        result = await score_risk(state)
        assert "risk_scores" in result
        assert "overall_score" in result

    @pytest.mark.asyncio()
    async def test_recommend_node(self):
        from shieldops.agents.security_awareness.nodes import (
            recommend,
            set_toolkit,
        )

        set_toolkit(SecurityAwarenessToolkit())
        state = SecurityAwarenessState(
            overall_score=50.0,
            risk_scores=[
                UserRiskScore(
                    user_id="u1",
                    department="finance",
                    risk_tier=RiskTier.HIGH,
                ),
            ],
            department_summaries=[
                DepartmentSummary(
                    department="finance",
                    phishing_fail_rate=55.0,
                    training_completion_pct=60.0,
                ),
            ],
        )
        result = await recommend(state)
        assert "recommendations" in result
        assert len(result["recommendations"]) > 0

    @pytest.mark.asyncio()
    async def test_report_node(self):
        from shieldops.agents.security_awareness.nodes import (
            report,
            set_toolkit,
        )

        set_toolkit(SecurityAwarenessToolkit())
        state = SecurityAwarenessState(
            overall_score=65.0,
            risk_scores=[],
            department_summaries=[],
            phishing_results=[],
            training_records=[],
            recommendations=["Train more"],
            reasoning_chain=[],
        )
        result = await report(state)
        assert result["stage"] == AwarenessStage.REPORT
        assert "report_summary" in result


# -------------------------------------------------------------------
# Runner
# -------------------------------------------------------------------


class TestRunner:
    def test_runner_init(self):
        from shieldops.agents.security_awareness.runner import (
            SecurityAwarenessRunner,
        )

        runner = SecurityAwarenessRunner()
        assert runner is not None
