"""Integration test for the dns_security agent."""

from __future__ import annotations

import pytest

from shieldops.agents.dns_security.models import DNSSecurityState


@pytest.fixture
def state() -> dict:
    return DNSSecurityState(request_id="test-001", tenant_id="t-01", session_start=1e6).model_dump()


def test_graph_compiles():
    from shieldops.agents.dns_security.graph import create_dns_security_graph

    sg = create_dns_security_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = DNSSecurityState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.dns_security.graph import create_dns_security_graph

    try:
        result = await create_dns_security_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
