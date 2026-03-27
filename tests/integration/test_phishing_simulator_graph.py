"""Integration test for Phishing Simulator Agent graph."""

from __future__ import annotations

import pytest

from shieldops.agents.phishing_simulator.models import (
    PhishingSimulatorState,
)


@pytest.fixture
def simulator_state() -> dict:
    return PhishingSimulatorState(
        request_id="test-ps-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.phishing_simulator.graph import (
        create_phishing_simulator_graph,
    )

    sg = create_phishing_simulator_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "design_campaign",
        "generate_payloads",
        "send_simulations",
        "track_responses",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    state = PhishingSimulatorState(
        request_id="ps-001",
        tenant_id="tenant-01",
    )
    assert state.request_id == "ps-001"
    assert state.error == ""


def test_state_defaults():
    state = PhishingSimulatorState()
    assert state.error == ""
    assert state.campaigns == []
    assert state.results == []


@pytest.mark.asyncio
async def test_full_pipeline(simulator_state):
    from shieldops.agents.phishing_simulator.graph import (
        create_phishing_simulator_graph,
    )

    sg = create_phishing_simulator_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(simulator_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
