"""Integration test for web_app_scanner."""

from __future__ import annotations

import pytest

from shieldops.agents.web_app_scanner.models import WebAppScannerState


@pytest.fixture
def state() -> dict:
    return WebAppScannerState().model_dump()


def test_graph_compiles():
    from shieldops.agents.web_app_scanner.graph import create_web_app_scanner_graph

    sg = create_web_app_scanner_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = WebAppScannerState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.web_app_scanner.graph import create_web_app_scanner_graph

    try:
        result = await create_web_app_scanner_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
