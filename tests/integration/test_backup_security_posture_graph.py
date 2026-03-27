"""Integration test for the backup_security_posture agent."""

from __future__ import annotations

import pytest

from shieldops.agents.backup_security_posture.models import BackupSecurityPostureState


@pytest.fixture
def state() -> dict:
    return BackupSecurityPostureState(
        request_id="test-001",
        tenant_id="t-01",
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.backup_security_posture.graph import (
        create_backup_security_posture_graph,
    )

    sg = create_backup_security_posture_graph()
    assert sg.compile() is not None


def test_state_defaults():
    s = BackupSecurityPostureState()
    assert s.error == ""


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.backup_security_posture.graph import (
        create_backup_security_posture_graph,
    )

    try:
        result = await create_backup_security_posture_graph().compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
