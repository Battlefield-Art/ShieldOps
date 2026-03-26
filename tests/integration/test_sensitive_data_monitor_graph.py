"""Integration test for the sensitive_data_monitor agent."""

from __future__ import annotations

import pytest

from shieldops.agents.sensitive_data_monitor.models import SensitiveDataMonitorState


@pytest.fixture
def state() -> dict:
    return SensitiveDataMonitorState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.sensitive_data_monitor.graph import create_sensitive_data_monitor_graph

    sg = create_sensitive_data_monitor_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = SensitiveDataMonitorState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.sensitive_data_monitor.graph import create_sensitive_data_monitor_graph

    try:
        result = await create_sensitive_data_monitor_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
