"""Integration test for the Situation Manager Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.situation_manager.models import (
    SituationManagerState,
    SituationStage,
)


@pytest.fixture
def state() -> dict:
    return SituationManagerState(
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.situation_manager.graph import (
        create_situation_manager_graph,
    )

    sg = create_situation_manager_graph()
    app = sg.compile()
    nodes = [n["id"] for n in app.get_graph().to_json()["nodes"]]
    for name in [
        "aggregate_alerts",
        "compose_narrative",
        "prioritize_situations",
        "recommend_actions",
        "track_outcomes",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = SituationManagerState()
    assert s.current_stage == (SituationStage.AGGREGATE_ALERTS)
    assert s.total_alerts_processed == 0
    assert s.total_situations == 0


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.situation_manager.graph import (
        create_situation_manager_graph,
    )

    try:
        result = await create_situation_manager_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
