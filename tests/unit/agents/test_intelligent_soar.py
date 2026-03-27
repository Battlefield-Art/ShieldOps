"""Tests for shieldops.agents.intelligent_soar."""

from __future__ import annotations

import pytest

from shieldops.agents.intelligent_soar.models import (
    AdaptiveDecision,
    ExecutionMode,
    ExecutionStep,
    IntelligentSOARState,
    OutcomeValidation,
    PlaybookSelection,
    PlaybookType,
    SOARReasoningStep,
    SOARStage,
    SOARTrigger,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_soar_stage_values(self) -> None:
        assert SOARStage.receive_trigger == "receive_trigger"
        assert SOARStage.select_playbook == "select_playbook"
        assert SOARStage.execute_steps == "execute_steps"
        assert SOARStage.adapt_dynamically == "adapt_dynamically"
        assert SOARStage.validate_outcome == "validate_outcome"
        assert SOARStage.report == "report"
        assert len(SOARStage) == 6

    def test_playbook_type_values(self) -> None:
        assert PlaybookType.investigation == "investigation"
        assert PlaybookType.containment == "containment"
        assert PlaybookType.eradication == "eradication"
        assert PlaybookType.recovery == "recovery"
        assert PlaybookType.compliance == "compliance"
        assert len(PlaybookType) == 5

    def test_execution_mode_values(self) -> None:
        assert ExecutionMode.automatic == "automatic"
        assert ExecutionMode.semi_automatic == "semi_automatic"
        assert ExecutionMode.manual == "manual"
        assert ExecutionMode.dry_run == "dry_run"
        assert len(ExecutionMode) == 4


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_state_defaults(self) -> None:
        state = IntelligentSOARState()
        assert state.session_id == ""
        assert state.tenant_id == ""
        assert state.execution_mode == ExecutionMode.automatic
        assert state.trigger is None
        assert state.selected_playbook is None
        assert state.execution_steps == []
        assert state.adaptive_decisions == []
        assert state.outcomes is None
        assert state.playbooks_executed == 0
        assert state.steps_completed == 0
        assert state.adaptation_rate == 0.0
        assert state.current_step == "init"
        assert state.error == ""

    def test_soar_trigger_defaults(self) -> None:
        trigger = SOARTrigger()
        assert trigger.trigger_id == ""
        assert trigger.severity == "medium"
        assert trigger.raw_payload == {}
        assert trigger.indicators == []
        assert trigger.timestamp is None

    def test_playbook_selection_defaults(self) -> None:
        ps = PlaybookSelection()
        assert ps.playbook_type == PlaybookType.investigation
        assert ps.match_score == 0.0
        assert ps.requires_approval is False

    def test_execution_step_defaults(self) -> None:
        step = ExecutionStep()
        assert step.status == "pending"
        assert step.result == {}
        assert step.was_adapted is False

    def test_adaptive_decision_defaults(self) -> None:
        ad = AdaptiveDecision()
        assert ad.confidence == 0.0
        assert ad.reasoning == ""

    def test_outcome_validation_defaults(self) -> None:
        ov = OutcomeValidation()
        assert ov.validated is False
        assert ov.threat_neutralized is False
        assert ov.residual_risk == 1.0
        assert ov.evidence == []
        assert ov.recommendations == []

    def test_reasoning_step_requires_fields(self) -> None:
        step = SOARReasoningStep(
            step_number=1,
            action="trigger",
            input_summary="in",
            output_summary="out",
        )
        assert step.step_number == 1
        assert step.tool_used is None


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.intelligent_soar.tools import IntelligentSOARToolkit

        return IntelligentSOARToolkit()

    @pytest.mark.asyncio
    async def test_ingest_trigger(self, toolkit) -> None:
        result = await toolkit.ingest_trigger(
            trigger_data={
                "source": "siem",
                "alert_type": "malware_detected",
                "severity": "critical",
                "raw_payload": {"host": "prod-01"},
                "indicators": ["evil.exe"],
            }
        )
        assert isinstance(result, dict)
        assert "trigger_id" in result

    @pytest.mark.asyncio
    async def test_select_playbook_returns_list(self, toolkit) -> None:
        result = await toolkit.select_playbook(
            alert_type="malware_detected",
            severity="critical",
            indicators=["evil.exe"],
        )
        assert isinstance(result, list)
        assert len(result) >= 1
        assert "playbook_id" in result[0]

    @pytest.mark.asyncio
    async def test_execute_step(self, toolkit) -> None:
        result = await toolkit.execute_step(
            step_name="isolate_endpoint",
            target="host-01",
            vendor="crowdstrike",
            execution_mode="automatic",
        )
        assert isinstance(result, dict)
        assert "status" in result

    @pytest.mark.asyncio
    async def test_evaluate_adaptation(self, toolkit) -> None:
        result = await toolkit.evaluate_adaptation(
            completed_steps=[{"step_name": "isolate_endpoint", "status": "completed"}],
            remaining_steps=["analyze_binary"],
            findings={"artifacts": 5},
        )
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_validate_outcome(self, toolkit) -> None:
        result = await toolkit.validate_outcome(
            execution_results=[{"status": "completed"}],
            trigger_indicators=["evil.exe"],
        )
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_track_effectiveness(self, toolkit) -> None:
        await toolkit.track_effectiveness(
            playbook_id="pb-investigate-malware",
            success_rate=0.9,
            adaptation_count=2,
        )
        # No exception = success

    @pytest.mark.asyncio
    async def test_record_metric(self, toolkit) -> None:
        await toolkit.record_metric(
            metric_type="soar.steps_completed",
            value=5,
        )
        # No exception = success

    def test_playbook_registry_initialized(self, toolkit) -> None:
        assert len(toolkit._playbook_registry) >= 1
        assert "pb-investigate-malware" in toolkit._playbook_registry


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.intelligent_soar.graph import create_intelligent_soar_graph

        graph = create_intelligent_soar_graph()
        compiled = graph.compile()
        assert compiled is not None

    def test_should_continue_routes_on_error(self) -> None:
        from shieldops.agents.intelligent_soar.graph import should_continue

        state = IntelligentSOARState(error="something broke")
        assert should_continue(state) == "report"

    def test_should_continue_routes_to_select(self) -> None:
        from shieldops.agents.intelligent_soar.graph import should_continue

        state = IntelligentSOARState()
        assert should_continue(state) == "select_playbook"

    def test_should_adapt_dry_run_skips(self) -> None:
        from shieldops.agents.intelligent_soar.graph import should_adapt

        state = IntelligentSOARState(execution_mode=ExecutionMode.dry_run)
        assert should_adapt(state) == "validate_outcome"
