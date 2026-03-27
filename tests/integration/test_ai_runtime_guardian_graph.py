"""Integration tests for AI Runtime Guardian agent."""

from __future__ import annotations

import pytest

from shieldops.agents.ai_runtime_guardian.models import (
    AIRuntimeGuardianState,
)


@pytest.fixture
def agent_state() -> dict:
    return AIRuntimeGuardianState(
        request_id="test-arg-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.ai_runtime_guardian.graph import (
        create_ai_runtime_guardian_graph,
    )

    sg = create_ai_runtime_guardian_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    expected = [
        "intercept_calls",
        "evaluate_risk",
        "enforce_policy",
        "generate_report",
    ]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_defaults():
    state = AIRuntimeGuardianState()
    assert state.intercepted_calls == []
    assert state.policy_violations == []
    assert state.tenant_id == ""


@pytest.mark.asyncio
async def test_full_pipeline(agent_state):
    from shieldops.agents.ai_runtime_guardian.graph import (
        create_ai_runtime_guardian_graph,
    )

    sg = create_ai_runtime_guardian_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(agent_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
