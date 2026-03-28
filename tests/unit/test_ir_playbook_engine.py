"""Unit tests for ir_playbook_engine agent."""

from __future__ import annotations

import pytest

from shieldops.agents.ir_playbook_engine.models import (
    ContainmentValidation,
    IncidentClassification,
    IncidentType,
    IRPlaybookEngineState,
    IRStage,
    PlaybookSelection,
    PlaybookStatus,
    ResponseAdaptation,
    StepExecution,
)
from shieldops.agents.ir_playbook_engine.tools import (
    PLAYBOOK_TEMPLATES,
    IRPlaybookEngineToolkit,
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class TestEnums:
    def test_ir_stage_values(self):
        assert IRStage.CLASSIFY_INCIDENT == "classify_incident"
        assert IRStage.REPORT == "report"

    def test_incident_type_values(self):
        assert IncidentType.RANSOMWARE == "ransomware"
        assert IncidentType.DDOS == "ddos"

    def test_playbook_status_values(self):
        assert PlaybookStatus.EXECUTING == "executing"
        assert PlaybookStatus.ADAPTED == "adapted"


class TestState:
    def test_defaults(self):
        state = IRPlaybookEngineState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.error == ""
        assert state.stage == IRStage.CLASSIFY_INCIDENT
        assert state.incident == {}
        assert state.step_results == []
        assert state.adaptations == []
        assert state.containment_checks == []
        assert state.reasoning_chain == []
        assert state.session_start == 0.0
        assert state.session_duration_ms == 0

    def test_with_values(self):
        state = IRPlaybookEngineState(
            request_id="req-1",
            tenant_id="t-1",
            incident={"id": "inc-1", "title": "malware detected"},
        )
        assert state.request_id == "req-1"
        assert state.tenant_id == "t-1"
        assert state.incident["id"] == "inc-1"


class TestModels:
    def test_incident_classification_defaults(self):
        cls = IncidentClassification()
        assert cls.id == ""
        assert cls.incident_type == IncidentType.MALWARE
        assert cls.confidence == 0.0
        assert cls.indicators == []

    def test_playbook_selection_defaults(self):
        ps = PlaybookSelection()
        assert ps.playbook_name == ""
        assert ps.steps == []
        assert ps.automation_level == "semi_automated"

    def test_step_execution_defaults(self):
        se = StepExecution()
        assert se.status == "pending"
        assert se.automated is False

    def test_response_adaptation_defaults(self):
        ra = ResponseAdaptation()
        assert ra.trigger == ""
        assert ra.confidence == 0.0

    def test_containment_validation_defaults(self):
        cv = ContainmentValidation()
        assert cv.passed is False
        assert cv.evidence == ""


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        return IRPlaybookEngineToolkit()

    @pytest.mark.asyncio
    async def test_classify_incident_malware(self, toolkit):
        incident = {
            "id": "inc-1",
            "title": "malware detected on server",
            "description": "Trojan found with c2 beacon activity",
            "severity": "critical",
        }
        result = await toolkit.classify_incident(incident)
        assert isinstance(result, IncidentClassification)
        assert result.incident_type == IncidentType.MALWARE
        assert result.severity == "critical"
        assert result.confidence > 0.0
        assert result.id.startswith("cls-")

    @pytest.mark.asyncio
    async def test_classify_incident_ransomware(self, toolkit):
        incident = {
            "id": "inc-2",
            "title": "ransomware encrypted files",
            "description": "ransom note found, locked files everywhere",
        }
        result = await toolkit.classify_incident(incident)
        assert result.incident_type == IncidentType.RANSOMWARE

    @pytest.mark.asyncio
    async def test_classify_incident_unknown_defaults(self, toolkit):
        incident = {"id": "inc-3", "title": "something happened"}
        result = await toolkit.classify_incident(incident)
        assert isinstance(result, IncidentClassification)
        # Should still classify (fallback to best match or malware default)

    @pytest.mark.asyncio
    async def test_select_playbook(self, toolkit):
        classification = IncidentClassification(
            incident_type=IncidentType.PHISHING,
            severity="high",
            confidence=0.8,
        )
        result = await toolkit.select_playbook(classification)
        assert isinstance(result, PlaybookSelection)
        assert result.playbook_name == "phishing_response_v2"
        assert len(result.steps) == len(PLAYBOOK_TEMPLATES[IncidentType.PHISHING]["steps"])
        assert result.id.startswith("pb-")

    @pytest.mark.asyncio
    async def test_select_playbook_automation_level(self, toolkit):
        classification = IncidentClassification(
            incident_type=IncidentType.DDOS,
        )
        result = await toolkit.select_playbook(classification)
        # DDOS has 3 auto + 1 manual -> semi_automated
        assert result.automation_level == "semi_automated"

    @pytest.mark.asyncio
    async def test_execute_step(self, toolkit):
        step = {"name": "isolate_host", "auto": True}
        result = await toolkit.execute_step(step, 0)
        assert isinstance(result, StepExecution)
        assert result.step_name == "isolate_host"
        assert result.status == "completed"
        assert result.automated is True
        assert result.id.startswith("step-")

    @pytest.mark.asyncio
    async def test_execute_step_default_name(self, toolkit):
        result = await toolkit.execute_step({}, 5)
        assert result.step_name == "step_5"

    @pytest.mark.asyncio
    async def test_validate_containment_all_pass(self, toolkit):
        classification = IncidentClassification(
            incident_type=IncidentType.MALWARE,
        )
        steps = [
            StepExecution(status="completed"),
            StepExecution(status="completed"),
        ]
        checks = await toolkit.validate_containment(classification, steps)
        assert len(checks) == 3
        assert all(c.passed for c in checks)

    @pytest.mark.asyncio
    async def test_validate_containment_with_failures(self, toolkit):
        classification = IncidentClassification(
            incident_type=IncidentType.MALWARE,
        )
        steps = [
            StepExecution(status="completed"),
            StepExecution(status="failed"),
        ]
        checks = await toolkit.validate_containment(classification, steps)
        assert len(checks) == 3
        # steps_completed check should fail
        steps_check = next(c for c in checks if c.check_name == "steps_completed")
        assert steps_check.passed is False
        # no_failures check should fail
        no_fail = next(c for c in checks if c.check_name == "no_failures")
        assert no_fail.passed is False


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio
    async def test_classify_incident_node(self):
        from shieldops.agents.ir_playbook_engine.nodes import (
            classify_incident,
            set_toolkit,
        )

        set_toolkit(IRPlaybookEngineToolkit())
        state = IRPlaybookEngineState(
            request_id="req-1",
            incident={
                "id": "inc-1",
                "title": "phishing email detected",
                "description": "suspicious email credential harvest",
            },
        )
        result = await classify_incident(state)
        assert "classification" in result
        assert result["stage"] == IRStage.SELECT_PLAYBOOK
        assert len(result["reasoning_chain"]) > 0

    @pytest.mark.asyncio
    async def test_select_playbook_node(self):
        from shieldops.agents.ir_playbook_engine.nodes import (
            select_playbook,
            set_toolkit,
        )

        set_toolkit(IRPlaybookEngineToolkit())
        state = IRPlaybookEngineState(
            request_id="req-1",
            classification=IncidentClassification(
                incident_type=IncidentType.DDOS,
                confidence=0.9,
            ),
        )
        result = await select_playbook(state)
        assert "playbook" in result
        assert result["stage"] == IRStage.EXECUTE_STEPS

    @pytest.mark.asyncio
    async def test_execute_steps_node(self):
        from shieldops.agents.ir_playbook_engine.nodes import (
            execute_steps,
            set_toolkit,
        )

        set_toolkit(IRPlaybookEngineToolkit())
        state = IRPlaybookEngineState(
            request_id="req-1",
            playbook=PlaybookSelection(
                steps=[
                    {"name": "step_a", "auto": True},
                    {"name": "step_b", "auto": False},
                ],
            ),
        )
        result = await execute_steps(state)
        assert len(result["step_results"]) == 2
        assert result["stage"] == IRStage.ADAPT_RESPONSE

    @pytest.mark.asyncio
    async def test_validate_containment_node(self):
        from shieldops.agents.ir_playbook_engine.nodes import (
            set_toolkit,
            validate_containment,
        )

        set_toolkit(IRPlaybookEngineToolkit())
        state = IRPlaybookEngineState(
            request_id="req-1",
            classification=IncidentClassification(
                incident_type=IncidentType.MALWARE,
            ),
            step_results=[StepExecution(status="completed")],
        )
        result = await validate_containment(state)
        assert "containment_checks" in result
        assert result["stage"] == IRStage.REPORT

    @pytest.mark.asyncio
    async def test_report_node(self):
        import time

        from shieldops.agents.ir_playbook_engine.nodes import (
            report,
            set_toolkit,
        )

        set_toolkit(IRPlaybookEngineToolkit())
        state = IRPlaybookEngineState(
            request_id="req-1",
            session_start=time.time(),
            classification=IncidentClassification(
                incident_type=IncidentType.MALWARE,
            ),
            playbook=PlaybookSelection(playbook_name="test_pb"),
            step_results=[StepExecution(status="completed")],
            containment_checks=[ContainmentValidation(passed=True)],
        )
        result = await report(state)
        assert result["stage"] == IRStage.REPORT
        assert "session_duration_ms" in result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class TestRunner:
    def test_runner_init(self):
        from shieldops.agents.ir_playbook_engine.runner import (
            IRPlaybookEngineRunner,
        )

        runner = IRPlaybookEngineRunner()
        assert runner is not None
