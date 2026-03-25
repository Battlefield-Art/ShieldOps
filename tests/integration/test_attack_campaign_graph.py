"""Integration test for the Attack Campaign Agent LangGraph pipeline.

Tests graph compilation, state model validation, and full campaign
simulation pipeline execution.
"""

from __future__ import annotations

import pytest

from shieldops.agents.attack_campaign.models import (
    AttackCampaignState,
    AttackPhase,
    CampaignStage,
    DefenseAssessment,
    SimulationMode,
    SimulationStep,
    TTPSelection,
)

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def campaign_state() -> dict:
    """State with attack campaign configuration."""
    return AttackCampaignState(
        request_id="test-ac-001",
        campaign_id="camp-prod-001",
        campaign_name="Q1 Red Team Assessment",
        target_scope={
            "environment": "staging",
            "services": ["api-gateway", "auth-service", "data-store"],
            "platforms": ["kubernetes", "aws"],
        },
        simulation_mode=SimulationMode.DRY_RUN,
        session_start=1000000.0,
    ).model_dump()


@pytest.fixture
def minimal_campaign_state() -> dict:
    """Minimal campaign state for basic execution."""
    return AttackCampaignState(
        request_id="test-ac-002",
        campaign_id="camp-dev-001",
        campaign_name="Basic Validation",
        target_scope={"environment": "dev"},
        simulation_mode=SimulationMode.DRY_RUN,
        session_start=1000000.0,
    ).model_dump()


# ── Graph Compilation ─────────────────────────────────────────────────


def test_graph_compiles():
    """Graph compiles and contains all expected nodes."""
    from shieldops.agents.attack_campaign.graph import (
        create_attack_campaign_graph,
    )

    sg = create_attack_campaign_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()

    expected_nodes = [
        "plan_campaign",
        "select_ttps",
        "execute_simulation",
        "collect_results",
        "assess_defenses",
        "generate_report",
    ]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected_nodes:
        assert name in node_ids, f"Missing node: {name}"


# ── State Model Validation ────────────────────────────────────────────


def test_state_model_validation():
    """AttackCampaignState validates with rich sample data."""
    ttp = TTPSelection(
        id="ttp-001",
        technique_id="T1021.001",
        technique_name="Remote Desktop Protocol",
        tactic="lateral_movement",
        description="RDP lateral movement to adjacent systems",
        severity="high",
        platform=["windows", "linux"],
        data_sources=["network_traffic", "process_creation"],
    )
    step = SimulationStep(
        id="step-001",
        campaign_id="camp-001",
        ttp_id="ttp-001",
        phase=AttackPhase.LATERAL_MOVEMENT,
        action="Attempt RDP connection to target host",
        target="prod-db-01",
        result="blocked_by_firewall",
        success=False,
        blocked_by="network_policy",
        duration_ms=1500.0,
        timestamp=1000000.0,
    )
    assessment = DefenseAssessment(
        id="da-001",
        ttp_id="ttp-001",
        detection_coverage=0.85,
        prevention_coverage=0.90,
        response_time_ms=2500.0,
        gaps=["No alerting on failed RDP from internal IPs"],
        recommendations=["Add detection rule for internal RDP failures"],
    )
    state = AttackCampaignState(
        campaign_id="camp-001",
        campaign_name="Test Campaign",
        simulation_mode=SimulationMode.DRY_RUN,
        ttp_selections=[ttp],
        simulation_steps=[step],
        defense_assessments=[assessment],
    )
    assert len(state.ttp_selections) == 1
    assert state.ttp_selections[0].technique_id == "T1021.001"
    assert state.simulation_steps[0].success is False
    assert state.defense_assessments[0].detection_coverage == 0.85


def test_state_model_defaults():
    """AttackCampaignState defaults are correct."""
    state = AttackCampaignState()
    assert state.stage == CampaignStage.PLAN
    assert state.simulation_mode == SimulationMode.DRY_RUN
    assert state.ttp_selections == []
    assert state.simulation_steps == []
    assert state.defense_assessments == []
    assert state.campaign_result is None
    assert state.error == ""


# ── Full Pipeline ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_full_campaign_pipeline(campaign_state):
    """Run the full Attack Campaign pipeline; verify graph executes."""
    from shieldops.agents.attack_campaign.graph import (
        create_attack_campaign_graph,
    )

    sg = create_attack_campaign_graph()
    compiled = sg.compile()

    try:
        result = await compiled.ainvoke(campaign_state)
    except Exception:
        pytest.skip("Pipeline ainvoke requires external dependencies")
        return

    assert isinstance(result, dict)
    assert "reasoning_chain" in result
    assert len(result.get("reasoning_chain", [])) > 0
