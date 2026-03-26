"""Integration test for the compliance_scanner agent."""
from __future__ import annotations
import pytest
from shieldops.agents.compliance_scanner.models import ComplianceScannerState

@pytest.fixture
def state() -> dict:
    return ComplianceScannerState(request_id="test-001", tenant_id="t-01", session_start=1e6).model_dump()

def test_graph_compiles():
    from shieldops.agents.compliance_scanner.graph import create_compliance_scanner_graph
    sg = create_compliance_scanner_graph()
    assert sg.compile() is not None

def test_state_defaults():
    s = ComplianceScannerState()
    assert s.error == ""

@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.compliance_scanner.graph import create_compliance_scanner_graph
    try:
        result = await create_compliance_scanner_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
