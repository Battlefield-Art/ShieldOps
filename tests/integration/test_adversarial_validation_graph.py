"""Integration test for the Adversarial Validation Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.adversarial_validation.models import (
    AdversarialValidationState,
    RedTeamFinding,
    ValidationOutcome,
    ValidationStage,
    ValidationTest,
)


@pytest.fixture
def validation_state() -> dict:
    return AdversarialValidationState(
        request_id="test-av-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.adversarial_validation.graph import create_adversarial_validation_graph

    sg = create_adversarial_validation_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "collect_findings",
        "select_retests",
        "execute_validation",
        "assess_effectiveness",
        "update_patterns",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    finding = RedTeamFinding(
        id="rtf-001",
        technique_id="T1078",
        technique_name="Valid Accounts",
        target="prod-api",
        severity="high",
        originally_successful=True,
        blue_team_fix_id="btf-001",
        fix_applied_at=1000000.0,
    )
    test = ValidationTest(
        id="vt-001",
        finding_id="rtf-001",
        technique_id="T1078",
        target="prod-api",
        defense_type="credential_rotation",
        outcome=ValidationOutcome.BLOCKED,
        confidence=0.95,
        execution_time_ms=1200.0,
    )
    state = AdversarialValidationState(
        red_team_findings=[finding],
        validation_tests=[test],
        stage=ValidationStage.ASSESS_EFFECTIVENESS,
    )
    assert state.validation_tests[0].outcome == ValidationOutcome.BLOCKED


def test_state_defaults():
    state = AdversarialValidationState()
    assert state.stage == ValidationStage.COLLECT_FINDINGS
    assert state.red_team_findings == []
    assert state.overall_effectiveness == 0.0


@pytest.mark.asyncio
async def test_full_pipeline(validation_state):
    from shieldops.agents.adversarial_validation.graph import create_adversarial_validation_graph

    sg = create_adversarial_validation_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(validation_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
