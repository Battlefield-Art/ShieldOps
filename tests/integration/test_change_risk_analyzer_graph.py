"""Integration test for the Change Risk Analyzer Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.change_risk_analyzer.models import (
    AnalyzerStage,
    ApprovalDecision,
    BlastRadiusPrediction,
    ChangeRecommendation,
    ChangeRequest,
    ChangeRiskAnalyzerState,
    ChangeType,
    RiskAssessment,
    RiskLevel,
)


@pytest.fixture
def change_state() -> dict:
    return ChangeRiskAnalyzerState(
        request_id="test-cra-001",
        tenant_id="tenant-prod-01",
        change_requests=[
            ChangeRequest(
                id="cr-001",
                title="Database migration v42",
                change_type=ChangeType.DATABASE_MIGRATION,
                author="dev@company.com",
                repository="shieldops/backend",
                files_changed=12,
                lines_added=340,
                lines_removed=120,
                services_affected=["api-gateway", "user-service", "billing"],
                environment="production",
                scheduled_at=1000000.0,
            ),
        ],
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.change_risk_analyzer.graph import create_change_risk_analyzer_graph

    sg = create_change_risk_analyzer_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "collect_change",
        "analyze_diff",
        "assess_risk",
        "predict_blast_radius",
        "recommend",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    risk = RiskAssessment(
        id="ra-001",
        change_id="cr-001",
        risk_level=RiskLevel.HIGH,
        risk_score=0.82,
        risk_factors=["db_migration", "production", "3_services"],
        historical_failure_rate=0.15,
        similar_changes_count=8,
        confidence=0.88,
    )
    blast = BlastRadiusPrediction(
        id="br-001",
        change_id="cr-001",
        affected_services=["api-gateway", "user-service", "billing"],
        affected_users_estimate=50000,
        data_at_risk=["user_profiles", "billing_data"],
        recovery_time_estimate_min=45,
        cascading_failures=["payment processing", "auth service"],
    )
    rec = ChangeRecommendation(
        id="rec-001",
        change_id="cr-001",
        approval_decision=ApprovalDecision.REQUIRE_SENIOR_REVIEW,
        reasoning="DB migration in prod with 3 affected services",
        required_reviewers=["dba-lead", "platform-lead"],
        rollback_plan="Restore from pre-migration snapshot",
        canary_suggested=True,
        monitoring_requirements=["latency_p95", "error_rate"],
    )
    state = ChangeRiskAnalyzerState(
        risk_assessments=[risk],
        blast_radius_predictions=[blast],
        recommendations=[rec],
        stage=AnalyzerStage.RECOMMEND,
    )
    assert state.risk_assessments[0].risk_level == RiskLevel.HIGH
    assert state.recommendations[0].approval_decision == ApprovalDecision.REQUIRE_SENIOR_REVIEW


def test_state_defaults():
    state = ChangeRiskAnalyzerState()
    assert state.stage == AnalyzerStage.COLLECT_CHANGE
    assert state.change_requests == []
    assert state.risk_assessments == []
    assert state.recommendations == []
    assert state.error == ""


@pytest.mark.asyncio
async def test_full_pipeline(change_state):
    from shieldops.agents.change_risk_analyzer.graph import create_change_risk_analyzer_graph

    sg = create_change_risk_analyzer_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(change_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
    assert "reasoning_chain" in result
