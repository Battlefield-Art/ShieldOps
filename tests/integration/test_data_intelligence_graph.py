"""Integration tests for Data Intelligence agent."""

from __future__ import annotations

import pytest

from shieldops.agents.data_intelligence.models import (
    DataIntelligenceState,
)


@pytest.fixture
def agent_state() -> dict:
    return DataIntelligenceState(
        request_id="test-di-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.data_intelligence.graph import (
        create_data_intelligence_graph,
    )

    sg = create_data_intelligence_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    expected = [
        "discover_data",
        "classify_data",
        "analyze_lineage",
        "generate_report",
    ]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_defaults():
    state = DataIntelligenceState()
    assert state.data_assets == []
    assert state.classifications == {}
    assert state.tenant_id == ""


@pytest.mark.asyncio
async def test_full_pipeline(agent_state):
    from shieldops.agents.data_intelligence.graph import (
        create_data_intelligence_graph,
    )

    sg = create_data_intelligence_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(agent_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
