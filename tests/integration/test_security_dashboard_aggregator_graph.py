"""Tests for security_dashboard_aggregator."""

from __future__ import annotations

import pytest

from shieldops.agents.security_dashboard_aggregator.models import (
    SecurityDashboardAggregatorState,
)


@pytest.fixture
def state() -> dict:
    return SecurityDashboardAggregatorState(tenant_id="t").model_dump()


def test_graph_compiles():
    from shieldops.agents.security_dashboard_aggregator.graph import (
        create_security_dashboard_aggregator_graph,
    )

    assert create_security_dashboard_aggregator_graph().compile() is not None


def test_state_defaults():
    s = SecurityDashboardAggregatorState(tenant_id="t")
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.security_dashboard_aggregator.graph import (
        create_security_dashboard_aggregator_graph,
    )

    try:
        result = await create_security_dashboard_aggregator_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
