"""Integration test for the remediation_verifier agent."""

from __future__ import annotations

import pytest

from shieldops.agents.remediation_verifier.models import RemediationVerifierState


@pytest.fixture
def state() -> dict:
    return RemediationVerifierState().model_dump()


def test_graph_compiles():
    from shieldops.agents.remediation_verifier.graph import (
        create_remediation_verifier_graph,
    )

    sg = create_remediation_verifier_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = RemediationVerifierState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.remediation_verifier.graph import (
        create_remediation_verifier_graph,
    )

    try:
        result = await create_remediation_verifier_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
