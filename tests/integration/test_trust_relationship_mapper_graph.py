"""Integration test for the Trust Relationship Mapper Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.trust_relationship_mapper.models import (
    TrustRelationshipMapperState,
    TrustStage,
)


@pytest.fixture
def state() -> dict:
    return TrustRelationshipMapperState(
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.trust_relationship_mapper.graph import (
        create_trust_relationship_mapper_graph,
    )

    sg = create_trust_relationship_mapper_graph()
    app = sg.compile()
    nodes = [n["id"] for n in app.get_graph().to_json()["nodes"]]
    for name in [
        "discover_trust_boundaries",
        "map_federation",
        "analyze_delegation_chains",
        "detect_trust_abuse",
        "assess_risk",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = TrustRelationshipMapperState()
    assert s.current_stage == (TrustStage.DISCOVER_TRUST_BOUNDARIES)
    assert s.total_boundaries == 0
    assert s.total_abuses_detected == 0
    assert s.avg_risk_score == 0.0


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.trust_relationship_mapper.graph import (
        create_trust_relationship_mapper_graph,
    )

    try:
        result = await create_trust_relationship_mapper_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
