"""End-to-end integration tests for the Incident Commander Agent.

Tests the full LangGraph workflow: triage -> coordinate -> monitor -> close,
with mock backends (no real incident management, sub-agents, or escalation
needed). The toolkit has built-in mock fallback paths.
"""

from unittest.mock import patch

import pytest

from shieldops.agents.incident_commander.models import (
    CommandStage,
    EscalationStatus,
    IncidentCommanderState,
    IncidentContext,
    SeverityLevel,
)
from shieldops.agents.incident_commander.runner import IncidentCommanderRunner

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def sev2_production_incident():
    """Standard SEV2 production incident context."""
    return IncidentContext(
        alert_id="ALT-E2E-001",
        service="payment-api",
        environment="production",
        severity=SeverityLevel.SEV2,
        description="Payment API latency spike above 5s p99",
        tags=["latency", "payments"],
        affected_services=["payment-api", "checkout-ui"],
    )


@pytest.fixture
def sev1_critical_incident():
    """SEV1 critical incident with low confidence (should escalate)."""
    return IncidentContext(
        alert_id="ALT-E2E-002",
        service="database-primary",
        environment="production",
        severity=SeverityLevel.SEV1,
        description="Primary database unresponsive, failover triggered",
        tags=["database", "outage"],
        affected_services=[
            "database-primary",
            "payment-api",
            "user-service",
            "order-service",
        ],
    )


@pytest.fixture
def sev3_staging_incident():
    """Low-severity staging incident."""
    return IncidentContext(
        alert_id="ALT-E2E-003",
        service="feature-flag-svc",
        environment="staging",
        severity=SeverityLevel.SEV3,
        description="Feature flag service returning stale configs",
        tags=["staging", "config"],
        affected_services=[],
    )


@pytest.fixture
def sev4_informational_incident():
    """Informational incident — SEV4."""
    return IncidentContext(
        alert_id="ALT-E2E-004",
        service="log-collector",
        environment="staging",
        severity=SeverityLevel.SEV4,
        description="Log collector memory usage slightly elevated",
        tags=["memory", "informational"],
        affected_services=[],
    )


# ── Full Pipeline: Resolution Path ───────────────────────────────────


@pytest.mark.asyncio
async def test_incident_commander_full_resolution(sev2_production_incident):
    """SEV2 production incident: triage -> coordinate -> resolve -> close."""
    with patch(
        "shieldops.agents.incident_commander.nodes.llm_structured",
        side_effect=RuntimeError("LLM unavailable"),
    ):
        runner = IncidentCommanderRunner()
        result = await runner.run(incident_context=sev2_production_incident)

    assert isinstance(result, IncidentCommanderState)
    assert result.error is None
    assert result.current_step == "complete"
    assert result.stage == CommandStage.REVIEW
    assert len(result.reasoning_chain) >= 3
    assert result.resolution_summary != ""
    assert result.confidence_score > 0


@pytest.mark.asyncio
async def test_incident_commander_dispatches_agents(sev2_production_incident):
    """SEV2 production incident dispatches investigation, remediation, and security."""
    with patch(
        "shieldops.agents.incident_commander.nodes.llm_structured",
        side_effect=RuntimeError("LLM unavailable"),
    ):
        runner = IncidentCommanderRunner()
        result = await runner.run(incident_context=sev2_production_incident)

    agent_types = [t.agent_type for t in result.agent_tasks]
    assert "investigation" in agent_types
    assert "remediation" in agent_types  # SEV2 triggers remediation
    assert "security" in agent_types  # production triggers security


@pytest.mark.asyncio
async def test_incident_commander_records_decisions(sev2_production_incident):
    """Commander records triage and resolution decisions."""
    with patch(
        "shieldops.agents.incident_commander.nodes.llm_structured",
        side_effect=RuntimeError("LLM unavailable"),
    ):
        runner = IncidentCommanderRunner()
        result = await runner.run(incident_context=sev2_production_incident)

    assert len(result.decisions) >= 2
    # First decision is triage, last should be resolve
    assert result.decisions[0].action == "triage_complete"
    assert result.decisions[-1].action == "resolve"


# ── Escalation Path ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_incident_commander_escalates_sev1(sev1_critical_incident):
    """SEV1 with mock tasks still 'dispatched' (not completed) should escalate."""
    # The mock fallback marks dispatched tasks as completed immediately,
    # so SEV1 normally resolves. We need to make check_agent_status return
    # "in_progress" to trigger escalation.
    with patch(
        "shieldops.agents.incident_commander.nodes.llm_structured",
        side_effect=RuntimeError("LLM unavailable"),
    ):
        runner = IncidentCommanderRunner()

        # Patch the toolkit's check_agent_status to return in-progress
        original_check = runner._toolkit.check_agent_status

        async def _in_progress(task_id):
            return {"task_id": task_id, "status": "in_progress", "findings": []}

        runner._toolkit.check_agent_status = _in_progress

        result = await runner.run(incident_context=sev1_critical_incident)

    assert isinstance(result, IncidentCommanderState)
    # SEV1 with unresolved tasks should escalate
    assert result.escalation_status == EscalationStatus.VP_ENG
    last_decision = result.decisions[-1]
    assert last_decision.action == "escalate"


@pytest.mark.asyncio
async def test_incident_commander_sev1_resolution_when_all_complete(
    sev1_critical_incident,
):
    """SEV1 with all tasks completed resolves normally (mock fallback path)."""
    with patch(
        "shieldops.agents.incident_commander.nodes.llm_structured",
        side_effect=RuntimeError("LLM unavailable"),
    ):
        runner = IncidentCommanderRunner()
        result = await runner.run(incident_context=sev1_critical_incident)

    # Default mock: all tasks complete -> resolve
    assert result.current_step == "complete"
    assert result.stage == CommandStage.REVIEW


# ── Staging (No Security Agent) ──────────────────────────────────────


@pytest.mark.asyncio
async def test_incident_commander_staging_no_security_agent(sev3_staging_incident):
    """Staging incident skips security agent dispatch."""
    with patch(
        "shieldops.agents.incident_commander.nodes.llm_structured",
        side_effect=RuntimeError("LLM unavailable"),
    ):
        runner = IncidentCommanderRunner()
        result = await runner.run(incident_context=sev3_staging_incident)

    agent_types = [t.agent_type for t in result.agent_tasks]
    assert "investigation" in agent_types
    # SEV3 should not include remediation
    assert "remediation" not in agent_types
    # staging should not include security
    assert "security" not in agent_types


# ── Reasoning Chain ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_incident_commander_reasoning_chain(sev2_production_incident):
    """Reasoning chain records triage, coordinate, monitor, and close steps."""
    with patch(
        "shieldops.agents.incident_commander.nodes.llm_structured",
        side_effect=RuntimeError("LLM unavailable"),
    ):
        runner = IncidentCommanderRunner()
        result = await runner.run(incident_context=sev2_production_incident)

    step_actions = [s.action for s in result.reasoning_chain]
    assert "triage" in step_actions
    assert "coordinate_agents" in step_actions
    assert "monitor_and_decide" in step_actions
    assert "close_incident" in step_actions


# ── Result Storage ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_incident_commander_stores_result(sev2_production_incident):
    """Runner stores completed run in its internal results dict."""
    with patch(
        "shieldops.agents.incident_commander.nodes.llm_structured",
        side_effect=RuntimeError("LLM unavailable"),
    ):
        runner = IncidentCommanderRunner()
        result = await runner.run(incident_context=sev2_production_incident)

    listed = runner.list_results()
    assert len(listed) == 1
    assert listed[0]["request_id"] == result.request_id

    retrieved = runner.get_result(result.request_id)
    assert retrieved is not None
    assert retrieved.request_id == result.request_id


# ── Blast Radius ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_incident_commander_identifies_blast_radius(sev2_production_incident):
    """Blast radius includes the primary service and affected services."""
    with patch(
        "shieldops.agents.incident_commander.nodes.llm_structured",
        side_effect=RuntimeError("LLM unavailable"),
    ):
        runner = IncidentCommanderRunner()
        result = await runner.run(incident_context=sev2_production_incident)

    assert "payment-api" in result.blast_radius
    assert len(result.blast_radius) >= 2


# ── SEV4 Minimal Response ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_incident_commander_sev4_minimal(sev4_informational_incident):
    """SEV4 staging incident gets investigation only, resolves quickly."""
    with patch(
        "shieldops.agents.incident_commander.nodes.llm_structured",
        side_effect=RuntimeError("LLM unavailable"),
    ):
        runner = IncidentCommanderRunner()
        result = await runner.run(incident_context=sev4_informational_incident)

    agent_types = [t.agent_type for t in result.agent_tasks]
    assert "investigation" in agent_types
    assert "remediation" not in agent_types
    assert "security" not in agent_types
    assert result.current_step == "complete"
