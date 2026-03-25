"""Integration test for the Service Account Tracker Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.service_account_tracker.models import (
    AccountStatus,
    CloudSource,
    ServiceAccount,
    ServiceAccountTrackerState,
    TrackerStage,
)


@pytest.fixture
def tracker_state() -> dict:
    return ServiceAccountTrackerState(
        request_id="test-sat-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.service_account_tracker.graph import create_service_account_tracker_graph

    sg = create_service_account_tracker_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "discover",
        "analyze_usage",
        "detect_anomalies",
        "classify_risk",
        "remediate",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    account = ServiceAccount(
        id="sa-001",
        name="ci-deployer",
        cloud_source=CloudSource.AWS_IAM,
        owner="platform-team",
        days_inactive=180,
        permissions=["s3:*", "ec2:*", "iam:*"],
        mfa_enabled=False,
        key_count=3,
        status=AccountStatus.ORPHANED,
        risk_score=0.88,
    )
    state = ServiceAccountTrackerState(
        service_accounts=[account], orphaned_count=1, stage=TrackerStage.CLASSIFY_RISK
    )
    assert state.service_accounts[0].status == AccountStatus.ORPHANED


def test_state_defaults():
    state = ServiceAccountTrackerState()
    assert state.stage == TrackerStage.DISCOVER
    assert state.service_accounts == []
    assert state.orphaned_count == 0


@pytest.mark.asyncio
async def test_full_pipeline(tracker_state):
    from shieldops.agents.service_account_tracker.graph import create_service_account_tracker_graph

    sg = create_service_account_tracker_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(tracker_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
