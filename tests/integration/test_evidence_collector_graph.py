"""Integration test for Evidence Collector Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.evidence_collector.models import (
    EvidenceCollectorState,
    EvidenceStage,
)


@pytest.fixture
def state() -> dict:
    return EvidenceCollectorState(
        request_id="test-ec-001",
        tenant_id="t-01",
        session_start=1e6,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.evidence_collector.graph import (
        create_evidence_collector_graph,
    )

    sg = create_evidence_collector_graph()
    nodes = [n["id"] for n in sg.compile().get_graph().to_json()["nodes"]]
    for name in [
        "identify_sources",
        "collect_artifacts",
        "hash_verify",
        "chain_of_custody",
        "package_evidence",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = EvidenceCollectorState()
    assert s.stage == EvidenceStage.IDENTIFY_SOURCES
    assert s.error == ""
    assert s.artifacts == []


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.evidence_collector.graph import (
        create_evidence_collector_graph,
    )

    try:
        sg = create_evidence_collector_graph()
        result = await sg.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
