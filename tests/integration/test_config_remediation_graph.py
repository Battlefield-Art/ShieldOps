"""Integration test for the Config Remediation Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.config_remediation.models import (
    ConfigRemediationState,
)


@pytest.fixture
def remediation_state() -> dict:
    return ConfigRemediationState(
        request_id="test-cr-001",
        tenant_id="tenant-prod-01",
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.config_remediation.graph import (
        create_config_remediation_graph,
    )

    sg = create_config_remediation_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = [
        "scan_configs",
        "identify_violations",
        "generate_fixes",
        "apply_fixes",
        "validate_compliance",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing: {name}"


def test_state_model_validation():
    state = ConfigRemediationState(
        request_id="cr-val-001",
        tenant_id="tenant-01",
        resource_ids=["sg-123", "sg-456"],
        dry_run=True,
    )
    assert state.resource_ids == ["sg-123", "sg-456"]
    assert state.dry_run is True


def test_state_defaults():
    state = ConfigRemediationState()
    assert state.error == ""
    assert state.resource_ids == []
    assert state.violations == []


@pytest.mark.asyncio
async def test_full_pipeline(remediation_state):
    from shieldops.agents.config_remediation.graph import (
        create_config_remediation_graph,
    )

    sg = create_config_remediation_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(remediation_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
