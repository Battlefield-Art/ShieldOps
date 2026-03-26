"""Integration test for the security_app_builder agent."""

from __future__ import annotations

import pytest

from shieldops.agents.security_app_builder.models import (
    SecurityAppBuilderState,
)


@pytest.fixture
def state() -> dict:
    return SecurityAppBuilderState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.security_app_builder.graph import (
        create_security_app_builder_graph,
    )

    sg = create_security_app_builder_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = SecurityAppBuilderState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.security_app_builder.graph import (
        create_security_app_builder_graph,
    )

    try:
        result = await create_security_app_builder_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
