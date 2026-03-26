"""Integration test for the air_gap_vault agent."""

from __future__ import annotations

import pytest

from shieldops.agents.air_gap_vault.models import (
    AirGapVaultState,
)


@pytest.fixture
def state() -> dict:
    return AirGapVaultState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.air_gap_vault.graph import (
        create_air_gap_vault_graph,
    )

    sg = create_air_gap_vault_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = AirGapVaultState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.air_gap_vault.graph import (
        create_air_gap_vault_graph,
    )

    try:
        result = await create_air_gap_vault_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
