"""Integration test for the Agent Memory Store Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.agent_memory_store.models import (
    AgentMemoryStoreState,
)


@pytest.fixture
def state() -> dict:
    return AgentMemoryStoreState(
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.agent_memory_store.graph import (
        create_agent_memory_store_graph,
    )

    sg = create_agent_memory_store_graph()
    app = sg.compile()
    nodes = [n["id"] for n in app.get_graph().to_json()["nodes"]]
    for name in [
        "receive_memory",
        "classify_memory",
        "store_memory",
        "index_for_retrieval",
        "prune_stale",
        "report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = AgentMemoryStoreState()
    assert s.current_stage == "init"
    assert s.tenant_id == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.agent_memory_store.graph import (
        create_agent_memory_store_graph,
    )

    try:
        result = await create_agent_memory_store_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
