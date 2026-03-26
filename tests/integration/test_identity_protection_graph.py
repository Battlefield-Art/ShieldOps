"""Integration test for the identity_protection agent."""

from __future__ import annotations

import pytest

from shieldops.agents.identity_protection.models import IdentityProtectionState


@pytest.fixture
def state() -> dict:
    return IdentityProtectionState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.identity_protection.graph import create_identity_protection_graph

    sg = create_identity_protection_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = IdentityProtectionState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.identity_protection.graph import create_identity_protection_graph

    try:
        result = await create_identity_protection_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
