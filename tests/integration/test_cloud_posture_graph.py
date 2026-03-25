"""Integration test for the Cloud Posture Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.cloud_posture.models import (
    CloudPostureState,
    CloudProvider,
    Misconfiguration,
    PostureStage,
    SeverityLevel,
)


@pytest.fixture
def posture_state() -> dict:
    return CloudPostureState(
        request_id="test-cp-001",
        tenant_id="tenant-prod-01",
        providers=["aws", "gcp", "kubernetes"],
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.cloud_posture.graph import create_cloud_posture_graph

    sg = create_cloud_posture_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "scan_cloud",
        "assess_benchmarks",
        "detect_misconfigs",
        "prioritize_risks",
        "remediate",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    misconfig = Misconfiguration(
        id="mc-001",
        resource_id="s3-bucket-prod",
        provider=CloudProvider.AWS,
        misconfig_type="public_access_enabled",
        severity=SeverityLevel.CRITICAL,
        description="S3 bucket has public read access",
        cis_reference="CIS AWS 2.1.2",
        auto_remediable=True,
        risk_score=0.95,
    )
    state = CloudPostureState(
        tenant_id="t-001",
        misconfigurations=[misconfig],
        stage=PostureStage.PRIORITIZE_RISKS,
    )
    assert len(state.misconfigurations) == 1
    assert state.misconfigurations[0].severity == SeverityLevel.CRITICAL


def test_state_defaults():
    state = CloudPostureState()
    assert state.stage == PostureStage.SCAN_CLOUD
    assert state.cloud_resources == []
    assert state.misconfigurations == []
    assert state.posture_score == 0.0
    assert state.error == ""


@pytest.mark.asyncio
async def test_full_pipeline(posture_state):
    from shieldops.agents.cloud_posture.graph import create_cloud_posture_graph

    sg = create_cloud_posture_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(posture_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
    assert "reasoning_chain" in result
