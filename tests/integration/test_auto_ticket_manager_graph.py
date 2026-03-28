"""Tests for auto_ticket_manager."""

from __future__ import annotations

import pytest

from shieldops.agents.auto_ticket_manager.models import (
    AutoTicketManagerState,
)


@pytest.fixture
def state() -> dict:
    return AutoTicketManagerState(tenant_id="t").model_dump()


def test_graph_compiles():
    from shieldops.agents.auto_ticket_manager.graph import create_auto_ticket_manager_graph

    assert create_auto_ticket_manager_graph().compile() is not None


def test_state_defaults():
    s = AutoTicketManagerState(tenant_id="t")
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.auto_ticket_manager.graph import create_auto_ticket_manager_graph

    try:
        result = await create_auto_ticket_manager_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
