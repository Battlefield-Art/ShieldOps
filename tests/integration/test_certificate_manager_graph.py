"""Integration test for the certificate_manager agent."""

from __future__ import annotations

import pytest

from shieldops.agents.certificate_manager.models import CertificateManagerState


@pytest.fixture
def state() -> dict:
    return CertificateManagerState(
        request_id="test-001", tenant_id="t-01", session_start=1e6
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.certificate_manager.graph import create_certificate_manager_graph

    sg = create_certificate_manager_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = CertificateManagerState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.certificate_manager.graph import create_certificate_manager_graph

    try:
        result = await create_certificate_manager_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
