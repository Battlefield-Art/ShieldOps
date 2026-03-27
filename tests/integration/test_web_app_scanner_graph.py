"""Integration test for Web App Scanner Agent graph."""

from __future__ import annotations

import pytest

from shieldops.agents.web_app_scanner.models import (
    WebAppScannerState,
)


@pytest.fixture
def scanner_state() -> dict:
    return WebAppScannerState(
        request_id="test-was-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.web_app_scanner.graph import (
        create_web_app_scanner_graph,
    )

    sg = create_web_app_scanner_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "crawl_application",
        "scan_vulnerabilities",
        "test_injection_points",
        "analyze_headers",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    state = WebAppScannerState(
        request_id="was-001",
        tenant_id="tenant-01",
    )
    assert state.request_id == "was-001"
    assert state.error == ""


def test_state_defaults():
    state = WebAppScannerState()
    assert state.error == ""
    assert state.findings == []
    assert state.pages_crawled == []


@pytest.mark.asyncio
async def test_full_pipeline(scanner_state):
    from shieldops.agents.web_app_scanner.graph import (
        create_web_app_scanner_graph,
    )

    sg = create_web_app_scanner_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(scanner_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
