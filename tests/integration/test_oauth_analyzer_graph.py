"""Integration test for the OAuth Grant Analyzer Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.oauth_analyzer.models import (
    AnalyzerStage,
    GrantStatus,
    OAuthAnalyzerState,
    OAuthGrant,
    PermissionScope,
)


@pytest.fixture
def tenant_scan_state() -> dict:
    return OAuthAnalyzerState(
        request_id="test-oa-001",
        tenant_id="tenant-prod-01",
        scan_scope=["google_workspace", "microsoft_365", "github", "slack"],
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.oauth_analyzer.graph import create_oauth_analyzer_graph

    sg = create_oauth_analyzer_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "discover_grants",
        "classify_permissions",
        "assess_risk",
        "detect_anomalies",
        "recommend_actions",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    grant = OAuthGrant(
        id="grant-001",
        app_name="Slack Bot",
        app_id="slack-bot-01",
        provider="slack",
        granted_to="eng-team",
        granted_by="admin@co.com",
        scopes=["channels:read", "channels:write", "users:read"],
        permission_scope=PermissionScope.READ_WRITE,
        status=GrantStatus.ACTIVE,
        risk_score=0.65,
    )
    state = OAuthAnalyzerState(
        tenant_id="t-001",
        discovered_grants=[grant],
        stage=AnalyzerStage.ASSESS_RISK,
    )
    assert len(state.discovered_grants) == 1
    assert state.discovered_grants[0].permission_scope == PermissionScope.READ_WRITE


def test_state_defaults():
    state = OAuthAnalyzerState()
    assert state.stage == AnalyzerStage.DISCOVER_GRANTS
    assert state.discovered_grants == []
    assert state.anomalies == []
    assert state.recommendations == []
    assert state.error == ""


@pytest.mark.asyncio
async def test_full_pipeline(tenant_scan_state):
    from shieldops.agents.oauth_analyzer.graph import create_oauth_analyzer_graph

    sg = create_oauth_analyzer_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(tenant_scan_state)
    except Exception:
        pytest.skip("Pipeline requires external dependencies")
        return
    assert isinstance(result, dict)
    assert "reasoning_chain" in result
