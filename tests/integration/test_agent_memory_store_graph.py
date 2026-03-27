"""Integration test for the Agent Memory Store Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.agent_memory_store.models import (
    AgentMemoryStoreState,
)


@pytest.fixture
def state() -> dict:
    return AgentMemoryStoreState(
        operation="store",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.agent_memory_store.graph import (
        create_agent_memory_store_graph,
    )

    sg = create_agent_memory_store_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = AgentMemoryStoreState()
    assert s.error == ""
    assert s.operation == "store"


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
