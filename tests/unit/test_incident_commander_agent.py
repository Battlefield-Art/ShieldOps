"""Tests for the Incident Commander Agent LangGraph workflow.

Covers:
- IncidentCommanderState model creation, defaults, and field types
- Sub-models: IncidentContext, AgentTask, CommandDecision, ReasoningStep
- Enums: CommandStage, SeverityLevel, EscalationStatus
- Prompt schemas: TriageResult, CoordinationResult, MonitoringResult, ResolutionResult
- IncidentCommanderToolkit initialization, triage, dispatch, escalation, resolution
- Graph creation (create_incident_commander_graph returns a StateGraph)
- IncidentCommanderRunner initialization and list_results
- Node functions (triage, coordinate_agents, monitor_and_decide, close_incident)
- Conditional edges (route_after_monitor)
- Integration: full workflow with simple inputs
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.agents.incident_commander.graph import (
    create_incident_commander_graph,
    route_after_monitor,
)
from shieldops.agents.incident_commander.models import (
    AgentTask,
    CommandDecision,
    CommandStage,
    EscalationStatus,
    IncidentCommanderState,
    IncidentContext,
    ReasoningStep,
    SeverityLevel,
)
from shieldops.agents.incident_commander.nodes import (
    _get_toolkit,
    close_incident,
    coordinate_agents,
    monitor_and_decide,
    set_toolkit,
    triage,
)
from shieldops.agents.incident_commander.prompts import (
    CoordinationResult,
    MonitoringResult,
    ResolutionResult,
    TriageResult,
)
from shieldops.agents.incident_commander.runner import IncidentCommanderRunner
from shieldops.agents.incident_commander.tools import IncidentCommanderToolkit


# -- Fixtures ----------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_toolkit():
    """Reset the module-level toolkit singleton between tests."""
    import shieldops.agents.incident_commander.nodes as nodes_mod

    original = nodes_mod._toolkit
    nodes_mod._toolkit = None
    yield
    nodes_mod._toolkit = original


@pytest.fixture
def sample_context() -> IncidentContext:
    return IncidentContext(
        alert_id="ALT-001",
        service="payment-api",
        environment="production",
        severity=SeverityLevel.SEV2,
        description="Payment API latency spike to 5s p99",
        tags=["latency", "payment"],
        affected_services=["payment-api", "checkout-service"],
    )


@pytest.fixture
def base_state(sample_context: IncidentContext) -> IncidentCommanderState:
    return IncidentCommanderState(
        request_id="ic-test-001",
        incident_context=sample_context,
    )


@pytest.fixture
def monitored_state(sample_context: IncidentContext) -> IncidentCommanderState:
    return IncidentCommanderState(
        request_id="ic-test-002",
        incident_context=sample_context,
        stage=CommandStage.RESOLVE,
        agent_tasks=[
            AgentTask(
                task_id="task-abc",
                agent_type="investigation",
                task_description="Investigate payment-api",
                status="dispatched",
            ),
        ],
        decisions=[
            CommandDecision(
                action="triage_complete",
                reasoning="Triaged as sev2",
                confidence=0.8,
            ),
        ],
        blast_radius=["payment-api", "checkout-service"],
        confidence_score=0.8,
    )


# -- TestEnums ---------------------------------------------------------------


class TestEnums:
    def test_command_stage_values(self):
        assert CommandStage.TRIAGE == "triage"
        assert CommandStage.INVESTIGATE == "investigate"
        assert CommandStage.COORDINATE == "coordinate"
        assert CommandStage.RESOLVE == "resolve"
        assert CommandStage.REVIEW == "review"

    def test_severity_level_values(self):
        assert SeverityLevel.SEV1 == "sev1"
        assert SeverityLevel.SEV2 == "sev2"
        assert SeverityLevel.SEV3 == "sev3"
        assert SeverityLevel.SEV4 == "sev4"

    def test_escalation_status_values(self):
        assert EscalationStatus.NONE == "none"
        assert EscalationStatus.TEAM_LEAD == "team_lead"
        assert EscalationStatus.VP_ENG == "vp_eng"
        assert EscalationStatus.CTO == "cto"


# -- TestState ---------------------------------------------------------------


class TestState:
    def test_default_values(self):
        state = IncidentCommanderState()
        assert state.request_id == ""
        assert state.stage == CommandStage.TRIAGE
        assert state.incident_context is None
        assert state.agent_tasks == []
        assert state.decisions == []
        assert state.resolution_summary == ""
        assert state.escalation_status == EscalationStatus.NONE
        assert state.confidence_score == pytest.approx(0.0)
        assert state.blast_radius == []
        assert state.session_start is None
        assert state.session_duration_ms == 0
        assert state.reasoning_chain == []
        assert state.current_step == "init"
        assert state.error is None

    def test_creation_with_context(self, base_state: IncidentCommanderState):
        assert base_state.request_id == "ic-test-001"
        assert base_state.incident_context is not None
        assert base_state.incident_context.alert_id == "ALT-001"

    def test_list_fields_are_independent(self):
        s1 = IncidentCommanderState()
        s2 = IncidentCommanderState()
        s1.agent_tasks.append(
            AgentTask(agent_type="investigation", task_description="test")
        )
        assert s2.agent_tasks == []

    def test_state_with_error(self):
        state = IncidentCommanderState(
            error="dispatch failed", current_step="failed"
        )
        assert state.error == "dispatch failed"
        assert state.current_step == "failed"


# -- TestSubModels -----------------------------------------------------------


class TestSubModels:
    def test_incident_context_creation(self, sample_context: IncidentContext):
        assert sample_context.alert_id == "ALT-001"
        assert sample_context.service == "payment-api"
        assert sample_context.environment == "production"
        assert sample_context.severity == SeverityLevel.SEV2
        assert len(sample_context.tags) == 2
        assert len(sample_context.affected_services) == 2

    def test_incident_context_defaults(self):
        ctx = IncidentContext(alert_id="A1", service="svc")
        assert ctx.environment == "production"
        assert ctx.severity == SeverityLevel.SEV3
        assert ctx.description == ""
        assert ctx.tags == []
        assert ctx.affected_services == []

    def test_agent_task_defaults(self):
        task = AgentTask(agent_type="investigation", task_description="check logs")
        assert task.task_id == ""
        assert task.status == "pending"
        assert task.result == {}

    def test_command_decision_defaults(self):
        decision = CommandDecision(action="resolve", reasoning="all clear")
        assert decision.confidence == pytest.approx(0.0)
        assert decision.requires_approval is False

    def test_reasoning_step_creation(self):
        step = ReasoningStep(
            step_number=1,
            action="triage",
            input_summary="Alert ALT-001",
            output_summary="Triaged as SEV2",
        )
        assert step.step_number == 1
        assert step.duration_ms == 0
        assert step.tool_used is None


# -- TestPromptSchemas -------------------------------------------------------


class TestPromptSchemas:
    def test_triage_result_fields(self):
        result = TriageResult(
            summary="Payment API latency spike",
            confirmed_severity="sev2",
            blast_radius=["payment-api", "checkout"],
            recommended_agents=["investigation", "remediation"],
            immediate_actions=["Enable circuit breaker"],
        )
        assert result.confirmed_severity == "sev2"
        assert len(result.blast_radius) == 2

    def test_coordination_result_fields(self):
        result = CoordinationResult(
            summary="Dispatched 3 agents",
            dispatched_agents=["investigation", "remediation", "security"],
            expected_duration_minutes=15,
            parallel_tasks=True,
        )
        assert result.expected_duration_minutes == 15
        assert result.parallel_tasks is True

    def test_monitoring_result_fields(self):
        result = MonitoringResult(
            summary="2 of 3 tasks complete",
            tasks_completed=2,
            tasks_pending=1,
            decision="continue_monitoring",
            reasoning="Security agent still running",
            confidence=0.6,
        )
        assert result.tasks_completed == 2
        assert result.decision == "continue_monitoring"

    def test_resolution_result_fields(self):
        result = ResolutionResult(
            summary="Incident resolved",
            root_cause="Database connection pool exhaustion",
            actions_taken=["Increased pool size", "Restarted service"],
            runbook_updates=["Add connection pool monitoring"],
            prevention_recommendations=["Auto-scale connection pools"],
        )
        assert len(result.actions_taken) == 2
        assert len(result.runbook_updates) == 1


# -- TestToolkit -------------------------------------------------------------


class TestToolkit:
    def test_toolkit_initialization_with_no_deps(self):
        toolkit = IncidentCommanderToolkit()
        assert toolkit._incident_client is None
        assert toolkit._agent_dispatcher is None
        assert toolkit._escalation_client is None
        assert toolkit._runbook_client is None

    def test_toolkit_initialization_with_deps(self):
        mock_client = MagicMock()
        toolkit = IncidentCommanderToolkit(incident_client=mock_client)
        assert toolkit._incident_client is mock_client

    def test_recommend_agents_sev1_production(self):
        context = IncidentContext(
            alert_id="A1",
            service="api",
            environment="production",
            severity=SeverityLevel.SEV1,
        )
        agents = IncidentCommanderToolkit._recommend_agents(
            SeverityLevel.SEV1, context
        )
        assert "investigation" in agents
        assert "remediation" in agents
        assert "security" in agents

    def test_recommend_agents_sev3_staging(self):
        context = IncidentContext(
            alert_id="A2",
            service="api",
            environment="staging",
            severity=SeverityLevel.SEV3,
        )
        agents = IncidentCommanderToolkit._recommend_agents(
            SeverityLevel.SEV3, context
        )
        assert "investigation" in agents
        assert "remediation" not in agents
        assert "security" not in agents

    @pytest.mark.asyncio
    async def test_triage_incident_mock_fallback(self, sample_context: IncidentContext):
        toolkit = IncidentCommanderToolkit()
        result = await toolkit.triage_incident(sample_context)
        assert result["alert_id"] == "ALT-001"
        assert "blast_radius" in result
        assert "recommended_agents" in result

    @pytest.mark.asyncio
    async def test_dispatch_agent_mock_fallback(self):
        toolkit = IncidentCommanderToolkit()
        task = await toolkit.dispatch_agent("investigation", "check logs")
        assert task.agent_type == "investigation"
        assert task.status == "dispatched"
        assert task.task_id.startswith("task-")

    @pytest.mark.asyncio
    async def test_check_agent_status_mock_fallback(self):
        toolkit = IncidentCommanderToolkit()
        result = await toolkit.check_agent_status("task-abc")
        assert result["task_id"] == "task-abc"
        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_escalate_mock_fallback(self):
        toolkit = IncidentCommanderToolkit()
        result = await toolkit.escalate(
            EscalationStatus.VP_ENG, "SEV1 not resolving"
        )
        assert result["level"] == "vp_eng"
        assert result["status"] == "escalated"

    @pytest.mark.asyncio
    async def test_resolve_incident_mock_fallback(self):
        toolkit = IncidentCommanderToolkit()
        result = await toolkit.resolve_incident("Fixed database connection pool")
        assert result["status"] == "resolved"
        assert "Fixed database" in result["summary"]

    @pytest.mark.asyncio
    async def test_dispatch_agent_with_backend(self):
        mock_dispatcher = AsyncMock()
        mock_dispatcher.dispatch.return_value = {
            "status": "running",
            "agent_id": "inv-123",
        }
        toolkit = IncidentCommanderToolkit(agent_dispatcher=mock_dispatcher)
        task = await toolkit.dispatch_agent("investigation", "check logs")
        assert task.status == "running"
        mock_dispatcher.dispatch.assert_awaited_once()


# -- TestGraph ---------------------------------------------------------------


class TestGraph:
    def test_create_incident_commander_graph_returns_state_graph(self):
        graph = create_incident_commander_graph()
        assert graph is not None
        assert hasattr(graph, "compile")

    def test_graph_has_expected_nodes(self):
        graph = create_incident_commander_graph()
        node_names = set(graph.nodes.keys())
        expected = {
            "triage",
            "coordinate_agents",
            "monitor_and_decide",
            "close_incident",
        }
        assert expected.issubset(node_names)

    def test_graph_compiles_without_error(self):
        graph = create_incident_commander_graph()
        app = graph.compile()
        assert app is not None


# -- TestRunner --------------------------------------------------------------


class TestRunner:
    def test_runner_initialization(self):
        with patch(
            "shieldops.agents.incident_commander.runner.create_incident_commander_graph"
        ) as mock_graph_fn:
            mock_graph = MagicMock()
            mock_graph.compile.return_value = MagicMock()
            mock_graph_fn.return_value = mock_graph
            runner = IncidentCommanderRunner()
            assert runner._results == {}

    def test_list_results_empty(self):
        with patch(
            "shieldops.agents.incident_commander.runner.create_incident_commander_graph"
        ) as mock_graph_fn:
            mock_graph = MagicMock()
            mock_graph.compile.return_value = MagicMock()
            mock_graph_fn.return_value = mock_graph
            runner = IncidentCommanderRunner()
            assert runner.list_results() == []

    @pytest.mark.asyncio
    async def test_run_handles_exception(self, sample_context: IncidentContext):
        mock_app = AsyncMock()
        mock_app.ainvoke.side_effect = RuntimeError("Graph failed")

        with patch(
            "shieldops.agents.incident_commander.runner.create_incident_commander_graph"
        ) as mock_graph_fn:
            mock_graph = MagicMock()
            mock_graph.compile.return_value = mock_app
            mock_graph_fn.return_value = mock_graph
            runner = IncidentCommanderRunner()
            result = await runner.run(incident_context=sample_context)

        assert result.error == "Graph failed"
        assert result.current_step == "failed"

    def test_get_result_not_found(self):
        with patch(
            "shieldops.agents.incident_commander.runner.create_incident_commander_graph"
        ) as mock_graph_fn:
            mock_graph = MagicMock()
            mock_graph.compile.return_value = MagicMock()
            mock_graph_fn.return_value = mock_graph
            runner = IncidentCommanderRunner()
            assert runner.get_result("nonexistent") is None


# -- TestNodes ---------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio
    async def test_triage_default_context(self):
        state = IncidentCommanderState(request_id="ic-triage-1")
        result = await triage(state)
        assert result["current_step"] == "triage"
        assert result["stage"] == CommandStage.COORDINATE
        assert "session_start" in result
        assert len(result["reasoning_chain"]) == 1
        assert len(result["decisions"]) == 1

    @pytest.mark.asyncio
    async def test_triage_with_context(self, base_state: IncidentCommanderState):
        result = await triage(base_state)
        assert result["stage"] == CommandStage.COORDINATE
        assert "payment-api" in result["blast_radius"]
        assert result["decisions"][0].action == "triage_complete"

    @pytest.mark.asyncio
    async def test_coordinate_agents_sev2_production(
        self, base_state: IncidentCommanderState
    ):
        # First triage
        triage_result = await triage(base_state)
        state = IncidentCommanderState(
            **{**base_state.model_dump(), **triage_result}
        )
        result = await coordinate_agents(state)
        assert result["current_step"] == "coordinate_agents"
        assert result["stage"] == CommandStage.RESOLVE
        # SEV2 + production: investigation + remediation + security
        assert len(result["agent_tasks"]) >= 2

    @pytest.mark.asyncio
    async def test_monitor_and_decide_all_completed(
        self, monitored_state: IncidentCommanderState
    ):
        result = await monitor_and_decide(monitored_state)
        assert result["current_step"] == "monitor_and_decide"
        # Mock fallback returns "completed" status
        latest_decision = result["decisions"][-1]
        assert latest_decision.action == "resolve"
        assert result["confidence_score"] == pytest.approx(0.9)

    @pytest.mark.asyncio
    async def test_close_incident(
        self, monitored_state: IncidentCommanderState
    ):
        result = await close_incident(monitored_state)
        assert result["current_step"] == "complete"
        assert result["stage"] == CommandStage.REVIEW
        assert "ALT-001" in result["resolution_summary"]
        assert len(result["reasoning_chain"]) > len(
            monitored_state.reasoning_chain
        )


# -- TestConditionalEdges ----------------------------------------------------


class TestConditionalEdges:
    def test_route_resolve(self):
        state = IncidentCommanderState(
            decisions=[
                CommandDecision(
                    action="resolve", reasoning="all clear", confidence=0.9
                )
            ],
        )
        assert route_after_monitor(state) == "close_incident"

    def test_route_escalate(self):
        from langgraph.graph import END

        state = IncidentCommanderState(
            decisions=[
                CommandDecision(
                    action="escalate", reasoning="SEV1 timeout", confidence=0.7
                )
            ],
        )
        assert route_after_monitor(state) == END

    def test_route_continue_monitoring(self):
        state = IncidentCommanderState(
            decisions=[
                CommandDecision(
                    action="continue_monitoring",
                    reasoning="tasks pending",
                    confidence=0.5,
                )
            ],
        )
        assert route_after_monitor(state) == "coordinate_agents"

    def test_route_with_error(self):
        from langgraph.graph import END

        state = IncidentCommanderState(error="something broke")
        assert route_after_monitor(state) == END

    def test_route_no_decisions(self):
        state = IncidentCommanderState(decisions=[])
        assert route_after_monitor(state) == "coordinate_agents"


# -- TestToolkitManagement ---------------------------------------------------


class TestToolkitManagement:
    def test_get_toolkit_returns_default_when_none_set(self):
        toolkit = _get_toolkit()
        assert isinstance(toolkit, IncidentCommanderToolkit)

    def test_set_toolkit_is_used_by_get_toolkit(self):
        custom = IncidentCommanderToolkit(incident_client=MagicMock())
        set_toolkit(custom)
        assert _get_toolkit() is custom


# -- TestIntegration ---------------------------------------------------------


class TestIntegration:
    @pytest.mark.asyncio
    async def test_full_workflow_sev3(self):
        """SEV3 incident: triage -> coordinate -> monitor (resolve) -> close."""
        context = IncidentContext(
            alert_id="ALT-INT-001",
            service="metrics-collector",
            environment="staging",
            severity=SeverityLevel.SEV3,
            description="Metrics delay",
        )
        state = IncidentCommanderState(
            request_id="ic-int-1",
            incident_context=context,
        )

        r1 = await triage(state)
        state = IncidentCommanderState(**{**state.model_dump(), **r1})
        assert state.current_step == "triage"
        assert state.stage == CommandStage.COORDINATE

        r2 = await coordinate_agents(state)
        state = IncidentCommanderState(**{**state.model_dump(), **r2})
        assert state.current_step == "coordinate_agents"
        assert len(state.agent_tasks) >= 1

        r3 = await monitor_and_decide(state)
        state = IncidentCommanderState(**{**state.model_dump(), **r3})
        assert state.current_step == "monitor_and_decide"
        # Mock completes all tasks, so decision should be resolve
        assert state.decisions[-1].action == "resolve"
        assert route_after_monitor(state) == "close_incident"

        r4 = await close_incident(state)
        assert r4["current_step"] == "complete"
        assert "ALT-INT-001" in r4["resolution_summary"]
