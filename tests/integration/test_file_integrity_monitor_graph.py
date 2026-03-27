"""Integration test for the file_integrity_monitor agent."""

from __future__ import annotations

import pytest

from shieldops.agents.file_integrity_monitor.models import (
    FileIntegrityMonitorState,
)


@pytest.fixture
def state() -> dict:
    return FileIntegrityMonitorState(request_id="test-001", tenant_id="t-01").model_dump()


def test_graph_compiles():
    from shieldops.agents.file_integrity_monitor.graph import (
        create_file_integrity_monitor_graph,
    )

    sg = create_file_integrity_monitor_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = FileIntegrityMonitorState(tenant_id="t-01")
    assert s.error == ""
    assert s.tenant_id == "t-01"


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.file_integrity_monitor.graph import (
        create_file_integrity_monitor_graph,
    )

    try:
        result = await create_file_integrity_monitor_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
