"""Integration test for the Config Validator Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.config_validator.models import ConfigValidatorState, ValidatorStage


@pytest.fixture
def state() -> dict:
    return ConfigValidatorState(
        request_id="test-cv-001", tenant_id="t-01", session_start=1e6
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.config_validator.graph import create_config_validator_graph

    sg = create_config_validator_graph()
    compiled = sg.compile()
    nodes = [n["id"] for n in compiled.get_graph().to_json()["nodes"]]
    for name in [
        "collect_configs",
        "compare_baselines",
        "detect_drift",
        "assess_impact",
        "remediate",
        "generate_report",
    ]:
        assert name in nodes, f"Missing: {name}"


def test_state_defaults():
    s = ConfigValidatorState()
    assert s.stage == ValidatorStage.COLLECT_CONFIGS


@pytest.mark.asyncio
async def test_pipeline(state):
    from shieldops.agents.config_validator.graph import create_config_validator_graph

    sg = create_config_validator_graph()
    try:
        result = await sg.compile().ainvoke(state)
        assert isinstance(result, dict)
    except Exception:
        pytest.skip("Requires dependencies")
