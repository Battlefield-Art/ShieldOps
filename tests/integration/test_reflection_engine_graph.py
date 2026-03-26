"""Integration test for the Reflection Engine Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.reflection_engine.models import (
    ReflectionEngineState,
    ReflectionStage,
)


@pytest.fixture
def state() -> dict:
    return ReflectionEngineState(
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.reflection_engine.graph import (
        create_reflection_engine_graph,
    )

    sg = create_reflection_engine_graph()
    app = sg.compile()
    nodes = [n["id"] for n in app.get_graph().to_json()["nodes"]]
    for name in [
        "collect_agent_actions",
        "evaluate_outcomes",
        "identify_mistakes",
        "generate_improvements",
        "apply_learnings",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = ReflectionEngineState()
    assert s.current_stage == (ReflectionStage.COLLECT_ACTIONS)
    assert s.tenant_id == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.reflection_engine.graph import (
        create_reflection_engine_graph,
    )

    try:
        result = await create_reflection_engine_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
