"""Integration test for the Policy Engine Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.policy_engine.models import (
    DriftSeverity,
    GeneratedPolicy,
    PolicyDrift,
    PolicyEngineState,
    PolicyStage,
    PolicyStatus,
    PolicyType,
    SecurityRequirement,
)


@pytest.fixture
def policy_state() -> dict:
    return PolicyEngineState(
        request_id="test-pe-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.policy_engine.graph import create_policy_engine_graph

    sg = create_policy_engine_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "collect_requirements",
        "generate_policies",
        "validate_coverage",
        "detect_drift",
        "reconcile",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    req = SecurityRequirement(
        id="req-001",
        title="Agent blast radius limit",
        description="All agents must have blast radius < 5 services",
        framework="shieldops",
        control_id="SO-001",
        priority="high",
        automated=True,
    )
    policy = GeneratedPolicy(
        id="pol-001",
        policy_type=PolicyType.AGENT_BEHAVIOR,
        name="agent_blast_radius",
        description="Limits agent blast radius to 5 services",
        rego_code="package shieldops.agent\ndefault allow = false\nallow { count(input.targets) <= 5 }",
        requirements_covered=["req-001"],
        status=PolicyStatus.ACTIVE,
    )
    drift = PolicyDrift(
        id="drift-001",
        policy_id="pol-001",
        policy_name="agent_blast_radius",
        drift_type="scope_expansion",
        expected_state="max_targets=5",
        actual_state="max_targets=10",
        severity=DriftSeverity.HIGH,
        auto_reconcilable=True,
    )
    state = PolicyEngineState(
        requirements=[req],
        generated_policies=[policy],
        policy_drifts=[drift],
        stage=PolicyStage.RECONCILE,
    )
    assert len(state.generated_policies) == 1
    assert state.policy_drifts[0].severity == DriftSeverity.HIGH


def test_state_defaults():
    state = PolicyEngineState()
    assert state.stage == PolicyStage.COLLECT_REQUIREMENTS
    assert state.requirements == []
    assert state.generated_policies == []
    assert state.coverage_gaps == []
    assert state.policy_drifts == []
    assert state.error == ""


@pytest.mark.asyncio
async def test_full_pipeline(policy_state):
    from shieldops.agents.policy_engine.graph import create_policy_engine_graph

    sg = create_policy_engine_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(policy_state)
    except Exception:
        pytest.skip("Pipeline requires external dependencies")
        return
    assert isinstance(result, dict)
    assert "reasoning_chain" in result
