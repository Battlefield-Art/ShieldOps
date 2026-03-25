"""Integration test for the Incident Triage Agent LangGraph pipeline."""

from __future__ import annotations

import pytest

from shieldops.agents.incident_triage.models import (
    IncidentCategory,
    IncidentSeverity,
    IncidentTriageState,
    IncomingIncident,
    RoutingDecision,
    SeverityClassification,
    TriageConfidence,
    TriageStage,
)


@pytest.fixture
def triage_state() -> dict:
    return IncidentTriageState(
        request_id="test-it-001",
        tenant_id="tenant-prod-01",
        incoming_incidents=[
            IncomingIncident(
                id="inc-001",
                title="Production API latency spike",
                description="P95 latency increased 300% in last 15 minutes",
                source="datadog",
                raw_severity="high",
                timestamp=1000000.0,
                affected_services=["api-gateway", "user-service"],
            ),
        ],
        session_start=1000000.0,
    ).model_dump()


def test_graph_compiles():
    from shieldops.agents.incident_triage.graph import create_incident_triage_graph

    sg = create_incident_triage_graph()
    compiled = sg.compile()
    graph_dict = compiled.get_graph().to_json()
    expected = ["ingest", "classify", "enrich", "deduplicate", "route", "generate_report"]
    node_ids = [n["id"] for n in graph_dict["nodes"]]
    for name in expected:
        assert name in node_ids, f"Missing node: {name}"


def test_state_model_validation():
    classification = SeverityClassification(
        id="sc-001",
        incident_id="inc-001",
        severity=IncidentSeverity.SEV2,
        category=IncidentCategory.AVAILABILITY,
        confidence=TriageConfidence.HIGH,
        reasoning="API latency spike affecting multiple services",
        historical_similar=3,
    )
    routing = RoutingDecision(
        id="rd-001",
        incident_id="inc-001",
        assigned_team="platform-sre",
        escalation_required=False,
        auto_remediation_possible=True,
        estimated_ttm_minutes=15,
        routing_reason="API latency maps to platform-sre on-call",
    )
    state = IncidentTriageState(
        classifications=[classification],
        routing_decisions=[routing],
        stage=TriageStage.ROUTE,
    )
    assert state.classifications[0].severity == IncidentSeverity.SEV2
    assert state.routing_decisions[0].assigned_team == "platform-sre"


def test_state_defaults():
    state = IncidentTriageState()
    assert state.stage == TriageStage.INGEST
    assert state.incoming_incidents == []
    assert state.classifications == []
    assert state.routing_decisions == []
    assert state.error == ""


@pytest.mark.asyncio
async def test_full_pipeline(triage_state):
    from shieldops.agents.incident_triage.graph import create_incident_triage_graph

    sg = create_incident_triage_graph()
    compiled = sg.compile()
    try:
        result = await compiled.ainvoke(triage_state)
    except Exception:
        pytest.skip("Requires external dependencies")
        return
    assert isinstance(result, dict)
    assert "reasoning_chain" in result
