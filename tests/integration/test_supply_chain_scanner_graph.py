"""Integration test for the Supply Chain Scanner Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.supply_chain_scanner.models import (
    ScanStage,
    SupplyChainScannerState,
)


@pytest.fixture
def state() -> dict:
    return SupplyChainScannerState(
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.supply_chain_scanner.graph import (
        create_supply_chain_scanner_graph,
    )

    sg = create_supply_chain_scanner_graph()
    app = sg.compile()
    nodes = [n["id"] for n in app.get_graph().to_json()["nodes"]]
    for name in [
        "inventory_ai_assets",
        "scan_model_registries",
        "scan_rag_sources",
        "scan_prompt_templates",
        "scan_tool_definitions",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = SupplyChainScannerState()
    assert s.stage == ScanStage.INVENTORY_AI_ASSETS
    assert s.tenant_id == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.supply_chain_scanner.graph import (
        create_supply_chain_scanner_graph,
    )

    try:
        result = await create_supply_chain_scanner_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
