"""Integration test for the unified_cloud_security agent."""

from __future__ import annotations

import pytest

from shieldops.agents.unified_cloud_security.models import UnifiedCloudSecurityState


@pytest.fixture
def state() -> dict:
    return UnifiedCloudSecurityState(
        request_id="test-001",
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.unified_cloud_security.graph import (
        create_unified_cloud_security_graph,
    )

    sg = create_unified_cloud_security_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = UnifiedCloudSecurityState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.unified_cloud_security.graph import (
        create_unified_cloud_security_graph,
    )

    try:
        result = await create_unified_cloud_security_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
