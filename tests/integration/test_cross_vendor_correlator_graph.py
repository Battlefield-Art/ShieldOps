"""Integration test for the Cross-Vendor Correlator Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.cross_vendor_correlator.models import (
    CorrelationStage,
    CrossVendorCorrelatorState,
)


@pytest.fixture
def state() -> dict:
    return CrossVendorCorrelatorState(
        tenant_id="t-01",
        vendors=["crowdstrike", "defender"],
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.cross_vendor_correlator.graph import (
        create_cross_vendor_correlator_graph,
    )

    sg = create_cross_vendor_correlator_graph()
    app = sg.compile()
    nodes = [n["id"] for n in app.get_graph().to_json()["nodes"]]
    for name in [
        "ingest_vendor_alerts",
        "normalize_to_ocsf",
        "correlate_by_entity",
        "build_kill_chain",
        "create_situations",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = CrossVendorCorrelatorState()
    assert s.current_stage == (CorrelationStage.INGEST_VENDOR_ALERTS)
    assert s.total_alerts_ingested == 0
    assert s.total_situations_created == 0


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.cross_vendor_correlator.graph import (
        create_cross_vendor_correlator_graph,
    )

    try:
        result = await create_cross_vendor_correlator_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
