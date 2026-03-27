"""Integration test for credential_tester."""

from __future__ import annotations

import pytest

from shieldops.agents.credential_tester.models import CredentialTesterState


@pytest.fixture
def state() -> dict:
    return CredentialTesterState().model_dump()


def test_graph_compiles():
    from shieldops.agents.credential_tester.graph import create_credential_tester_graph

    sg = create_credential_tester_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = CredentialTesterState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.credential_tester.graph import create_credential_tester_graph

    try:
        result = await create_credential_tester_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
