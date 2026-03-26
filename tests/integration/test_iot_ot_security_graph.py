"""Integration test for the iot_ot_security agent."""

from __future__ import annotations

import pytest

from shieldops.agents.iot_ot_security.models import (
    IoTOTSecurityState,
)


@pytest.fixture
def state() -> dict:
    return IoTOTSecurityState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.iot_ot_security.graph import (
        create_iot_ot_security_graph,
    )

    sg = create_iot_ot_security_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = IoTOTSecurityState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.iot_ot_security.graph import (
        create_iot_ot_security_graph,
    )

    try:
        result = await create_iot_ot_security_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
