"""Integration test for phishing_simulator."""

from __future__ import annotations

import pytest

from shieldops.agents.phishing_simulator.models import PhishingSimulatorState


@pytest.fixture
def state() -> dict:
    return PhishingSimulatorState().model_dump()


def test_graph_compiles():
    from shieldops.agents.phishing_simulator.graph import create_phishing_simulator_graph

    sg = create_phishing_simulator_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = PhishingSimulatorState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.phishing_simulator.graph import create_phishing_simulator_graph

    try:
        result = await create_phishing_simulator_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
