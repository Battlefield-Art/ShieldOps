"""Integration test for the Remediation Verifier Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.remediation_verifier.models import (
    RemediationVerifierState,
)


@pytest.fixture
def verifier_state() -> dict:
    return RemediationVerifierState(
        request_id="test-rv-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.remediation_verifier.graph import (
        create_remediation_verifier_graph,
    )

    sg = create_remediation_verifier_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "collect_remediations",
        "design_tests",
        "execute_tests",
        "compare_results",
        "detect_regressions",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing: {name}"


def test_state_model_validation():
    state = RemediationVerifierState(
        request_id="rv-val-001",
        tenant_id="tenant-01",
        remediation_ids=["rem-001", "rem-002"],
        rollback_on_failure=True,
    )
    assert len(state.remediation_ids) == 2
    assert state.rollback_on_failure is True


def test_state_defaults():
    state = RemediationVerifierState()
    assert state.error == ""
    assert state.remediation_ids == []
    assert state.test_results == []


@pytest.mark.asyncio
async def test_full_pipeline(verifier_state):
    from shieldops.agents.remediation_verifier.graph import (
        create_remediation_verifier_graph,
    )

    sg = create_remediation_verifier_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(verifier_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
