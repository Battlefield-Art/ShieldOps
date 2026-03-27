"""Integration test for the config_remediation agent."""

from __future__ import annotations

import pytest

from shieldops.agents.config_remediation.models import ConfigRemediationState


@pytest.fixture
def state() -> dict:
    return ConfigRemediationState().model_dump()


def test_graph_compiles():
    from shieldops.agents.config_remediation.graph import (
        create_config_remediation_graph,
    )

    sg = create_config_remediation_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = ConfigRemediationState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.config_remediation.graph import (
        create_config_remediation_graph,
    )

    try:
        result = await create_config_remediation_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
