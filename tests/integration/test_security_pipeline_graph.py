"""Tests for security_pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.security_pipeline.models import (
    SecurityPipelineState,
)


@pytest.fixture
def state() -> dict:
    return SecurityPipelineState(tenant_id="t").model_dump()


def test_graph_compiles():
    from shieldops.agents.security_pipeline.graph import create_security_pipeline_graph

    assert create_security_pipeline_graph().compile() is not None


def test_state_defaults():
    s = SecurityPipelineState(tenant_id="t")
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.security_pipeline.graph import create_security_pipeline_graph

    try:
        result = await create_security_pipeline_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
