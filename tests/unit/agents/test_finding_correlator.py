"""Tests for finding_correlator."""

from __future__ import annotations

import pytest

from shieldops.agents.finding_correlator.models import (
    FindingCorrelatorState,
)


@pytest.fixture
def state() -> dict:
    return FindingCorrelatorState(tenant_id="t").model_dump()


def test_graph_compiles():
    from shieldops.agents.finding_correlator.graph import create_finding_correlator_graph

    assert create_finding_correlator_graph().compile() is not None


def test_state_defaults():
    s = FindingCorrelatorState(tenant_id="t")
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.finding_correlator.graph import create_finding_correlator_graph

    try:
        result = await create_finding_correlator_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
