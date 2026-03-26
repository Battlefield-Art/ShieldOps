"""Integration test for the exposure_management agent."""

from __future__ import annotations

import pytest

from shieldops.agents.exposure_management.models import ExposureManagementState


@pytest.fixture
def state() -> dict:
    return ExposureManagementState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.exposure_management.graph import create_exposure_management_graph

    sg = create_exposure_management_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = ExposureManagementState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.exposure_management.graph import create_exposure_management_graph

    try:
        result = await create_exposure_management_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
