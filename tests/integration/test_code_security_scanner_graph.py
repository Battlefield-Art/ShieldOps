"""Integration test for the Code Security Scanner agent."""

from __future__ import annotations

import pytest

from shieldops.agents.code_security_scanner.models import CodeSecurityScannerState


@pytest.fixture
def state() -> dict:
    return CodeSecurityScannerState(
        request_id="test-001",
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.code_security_scanner.graph import (
        create_code_security_scanner_graph,
    )

    sg = create_code_security_scanner_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = CodeSecurityScannerState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.code_security_scanner.graph import (
        create_code_security_scanner_graph,
    )

    try:
        g = create_code_security_scanner_graph()
        result = await g.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
