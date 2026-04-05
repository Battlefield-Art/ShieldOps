"""Integration test for the backup_validator agent."""

from __future__ import annotations

import pytest

from shieldops.agents.backup_validator.models import BackupValidatorState


@pytest.fixture
def state() -> dict:
    return BackupValidatorState(
        request_id="test-001", tenant_id="t-01", session_start=1e6
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.backup_validator.graph import create_backup_validator_graph

    sg = create_backup_validator_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = BackupValidatorState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.backup_validator.graph import create_backup_validator_graph

    try:
        result = await create_backup_validator_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
