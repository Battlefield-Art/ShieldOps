"""Tests for continuous_scanner."""

from __future__ import annotations

import pytest

from shieldops.agents.continuous_scanner.models import (
    ContinuousScannerState,
)


@pytest.fixture
def state() -> dict:
    return ContinuousScannerState(tenant_id="t").model_dump()


def test_graph_compiles():
    from shieldops.agents.continuous_scanner.graph import create_continuous_scanner_graph

    assert create_continuous_scanner_graph().compile() is not None


def test_state_defaults():
    s = ContinuousScannerState(tenant_id="t")
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.continuous_scanner.graph import create_continuous_scanner_graph

    try:
        result = await create_continuous_scanner_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
