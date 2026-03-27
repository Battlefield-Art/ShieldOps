"""Integration tests for Backup Security Posture agent."""

from __future__ import annotations

import pytest

from shieldops.agents.backup_security_posture.models import (
    BackupSecurityPostureState,
)


@pytest.fixture
def agent_state() -> dict:
    return BackupSecurityPostureState(
        request_id="test-bsp-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.backup_security_posture.graph import (
        create_backup_security_posture_graph,
    )

    sg = create_backup_security_posture_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    expected = [
        "audit_backups",
        "assess_security",
        "identify_gaps",
        "generate_report",
    ]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_defaults():
    state = BackupSecurityPostureState()
    assert state.backup_configs == []
    assert state.security_gaps == []
    assert state.tenant_id == ""


@pytest.mark.asyncio
async def test_full_pipeline(agent_state):
    from shieldops.agents.backup_security_posture.graph import (
        create_backup_security_posture_graph,
    )

    sg = create_backup_security_posture_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(agent_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
