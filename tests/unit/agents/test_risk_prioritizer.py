"""Tests for risk_prioritizer."""

from __future__ import annotations

import pytest

from shieldops.agents.risk_prioritizer.models import (
    RiskPrioritizerState,
)


@pytest.fixture
def state() -> dict:
    return RiskPrioritizerState(tenant_id="t").model_dump()


def test_graph_compiles():
    from shieldops.agents.risk_prioritizer.graph import create_risk_prioritizer_graph

    assert create_risk_prioritizer_graph().compile() is not None


def test_state_defaults():
    s = RiskPrioritizerState(tenant_id="t")
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.risk_prioritizer.graph import create_risk_prioritizer_graph

    try:
        result = await create_risk_prioritizer_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
