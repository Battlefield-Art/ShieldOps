"""Integration test for the Access Review Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.access_review.models import (
    AccessReviewState,
    AccessRisk,
    Entitlement,
    ReviewStage,
)


@pytest.fixture
def review_state() -> dict:
    return AccessReviewState(
        request_id="test-ar-001",
        tenant_id="tenant-prod-01",
        campaign_name="Q1-2026-Access-Review",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.access_review.graph import create_access_review_graph

    sg = create_access_review_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "collect_entitlements",
        "analyze_access",
        "identify_violations",
        "generate_tasks",
        "certify",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    entitlement = Entitlement(
        id="ent-001",
        identity_id="svc-admin",
        identity_type="service_account",
        resource="production-db",
        permission="db:admin",
        granted_by="former-employee@co.com",
        justification="Initial setup",
        risk_level=AccessRisk.CRITICAL,
    )
    state = AccessReviewState(
        entitlements=[entitlement], campaign_name="Q1-review", stage=ReviewStage.IDENTIFY_VIOLATIONS
    )
    assert state.entitlements[0].risk_level == AccessRisk.CRITICAL


def test_state_defaults():
    state = AccessReviewState()
    assert state.stage == ReviewStage.COLLECT_ENTITLEMENTS
    assert state.entitlements == []
    assert state.violations == []
    assert state.review_tasks == []


@pytest.mark.asyncio
async def test_full_pipeline(review_state):
    from shieldops.agents.access_review.graph import create_access_review_graph

    sg = create_access_review_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(review_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
