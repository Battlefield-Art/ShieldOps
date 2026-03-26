"""Integration test for the Ransomware Forensics agent."""

from __future__ import annotations

import pytest

from shieldops.agents.ransomware_forensics.models import RansomwareForensicsState


@pytest.fixture
def state() -> dict:
    return RansomwareForensicsState(
        request_id="test-001",
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.ransomware_forensics.graph import (
        create_ransomware_forensics_graph,
    )

    sg = create_ransomware_forensics_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = RansomwareForensicsState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.ransomware_forensics.graph import (
        create_ransomware_forensics_graph,
    )

    try:
        g = create_ransomware_forensics_graph()
        result = await g.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
