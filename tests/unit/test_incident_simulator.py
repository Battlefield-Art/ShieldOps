"""Unit tests for incident_simulator agent."""

from __future__ import annotations

import pytest

from shieldops.agents.incident_simulator.models import (
    ExerciseDesign,
    ExerciseMode,
    ExerciseScope,
    IncidentSimulatorState,
    PerformanceMeasurement,
    PerformanceMetric,
    ReadinessScore,
    ResponseObservation,
    ScenarioInjection,
    ScenarioType,
    SimStage,
    TeamScore,
)
from shieldops.agents.incident_simulator.tools import (
    SCENARIO_TEMPLATES,
    IncidentSimulatorToolkit,
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class TestEnums:
    def test_sim_stage_values(self):
        assert SimStage.DESIGN_SCENARIO == "design_scenario"
        assert SimStage.REPORT == "report"

    def test_scenario_type_values(self):
        assert ScenarioType.RANSOMWARE == "ransomware"
        assert ScenarioType.APT == "apt"

    def test_exercise_mode_values(self):
        assert ExerciseMode.TABLETOP == "tabletop"
        assert ExerciseMode.RED_TEAM == "red_team"

    def test_exercise_scope_values(self):
        assert ExerciseScope.TABLETOP == "tabletop"
        assert ExerciseScope.FULL_SCALE == "full_scale"

    def test_performance_metric_values(self):
        assert PerformanceMetric.DETECTION_TIME == "detection_time"
        assert PerformanceMetric.ESCALATION_ACCURACY == "escalation_accuracy"


class TestState:
    def test_defaults(self):
        state = IncidentSimulatorState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.error == ""
        assert state.stage == SimStage.DESIGN_SCENARIO
        assert state.scenario_type == ScenarioType.RANSOMWARE
        assert state.exercise_mode == ExerciseMode.TABLETOP
        assert state.exercise is None
        assert state.injects == []
        assert state.observations == []
        assert state.measurements == []
        assert state.readiness is None
        assert state.team_scores == []
        assert state.readiness_score == 0.0
        assert state.report_summary == ""
        assert state.reasoning_chain == []
        assert state.session_start == 0.0
        assert state.duration_ms == 0

    def test_with_values(self):
        state = IncidentSimulatorState(
            request_id="req-1",
            tenant_id="t-1",
            scenario_type=ScenarioType.DATA_BREACH,
            exercise_mode=ExerciseMode.PURPLE_TEAM,
            readiness_score=85.0,
        )
        assert state.scenario_type == ScenarioType.DATA_BREACH
        assert state.exercise_mode == ExerciseMode.PURPLE_TEAM
        assert state.readiness_score == 85.0


class TestModels:
    def test_team_score_defaults(self):
        ts = TeamScore()
        assert ts.team_name == ""
        assert ts.overall == 0.0

    def test_exercise_design_defaults(self):
        ed = ExerciseDesign()
        assert ed.scope == ExerciseScope.TABLETOP
        assert ed.duration_min == 60
        assert ed.objectives == []

    def test_scenario_injection_defaults(self):
        si = ScenarioInjection()
        assert si.inject_number == 0
        assert si.severity == "medium"

    def test_response_observation_defaults(self):
        ro = ResponseObservation()
        assert ro.response_time_sec == 0.0
        assert ro.communication_quality == "adequate"

    def test_performance_measurement_defaults(self):
        pm = PerformanceMeasurement()
        assert pm.metric == PerformanceMetric.DETECTION_TIME
        assert pm.met_target is False

    def test_readiness_score_defaults(self):
        rs = ReadinessScore()
        assert rs.overall_score == 0.0
        assert rs.grade == "F"
        assert rs.strengths == []
        assert rs.gaps == []


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        return IncidentSimulatorToolkit()

    @pytest.mark.asyncio
    async def test_design_exercise_tabletop(self, toolkit):
        scenario = {"type": "ransomware", "scope": "tabletop"}
        result = await toolkit.design_exercise(scenario)
        assert isinstance(result, ExerciseDesign)
        assert result.id.startswith("ex-")
        assert result.scope == ExerciseScope.TABLETOP
        assert result.duration_min == 60
        assert result.injects_planned == len(SCENARIO_TEMPLATES["ransomware"])

    @pytest.mark.asyncio
    async def test_design_exercise_functional(self, toolkit):
        scenario = {"type": "data_breach", "scope": "functional"}
        result = await toolkit.design_exercise(scenario)
        assert result.scope == ExerciseScope.FUNCTIONAL
        assert result.duration_min == 120

    @pytest.mark.asyncio
    async def test_design_exercise_full_scale(self, toolkit):
        scenario = {"type": "default", "scope": "full_scale"}
        result = await toolkit.design_exercise(scenario)
        assert result.scope == ExerciseScope.FULL_SCALE
        assert result.duration_min == 240

    @pytest.mark.asyncio
    async def test_design_exercise_default_scenario(self, toolkit):
        scenario = {"type": "unknown_type", "scope": "tabletop"}
        result = await toolkit.design_exercise(scenario)
        assert result.injects_planned == len(SCENARIO_TEMPLATES["default"])

    @pytest.mark.asyncio
    async def test_create_injects(self, toolkit):
        exercise = ExerciseDesign(
            scenario_type="ransomware",
        )
        injects = await toolkit.create_injects(exercise)
        assert len(injects) == len(SCENARIO_TEMPLATES["ransomware"])
        for i, inj in enumerate(injects):
            assert isinstance(inj, ScenarioInjection)
            assert inj.inject_number == i + 1
            assert inj.id.startswith("inj-")

    @pytest.mark.asyncio
    async def test_observe_responses(self, toolkit):
        injects = [
            ScenarioInjection(
                id="inj-1",
                inject_number=1,
                title="Test inject",
            ),
            ScenarioInjection(
                id="inj-2",
                inject_number=2,
                title="Second inject",
            ),
        ]
        observations = await toolkit.observe_responses(injects)
        assert len(observations) == 2
        for obs in observations:
            assert isinstance(obs, ResponseObservation)
            assert obs.id.startswith("obs-")
            assert obs.response_time_sec > 0

    @pytest.mark.asyncio
    async def test_observe_responses_quality(self, toolkit):
        injects = [
            ScenarioInjection(id="inj-1", inject_number=1, title="Fast"),
        ]
        observations = await toolkit.observe_responses(injects)
        # inject_number=1 -> response_time=150s -> quality="good"
        assert observations[0].communication_quality == "good"

    @pytest.mark.asyncio
    async def test_measure_performance(self, toolkit):
        observations = [
            ResponseObservation(
                response_time_sec=100.0,
                communication_quality="good",
                decision_quality="good",
            ),
            ResponseObservation(
                response_time_sec=200.0,
                communication_quality="adequate",
                decision_quality="adequate",
            ),
        ]
        measurements = await toolkit.measure_performance(observations)
        assert len(measurements) == 3  # detection, communication, decision
        metrics = {m.metric for m in measurements}
        assert PerformanceMetric.DETECTION_TIME in metrics
        assert PerformanceMetric.COMMUNICATION_SPEED in metrics
        assert PerformanceMetric.DECISION_QUALITY in metrics

    @pytest.mark.asyncio
    async def test_measure_performance_empty(self, toolkit):
        measurements = await toolkit.measure_performance([])
        assert measurements == []

    @pytest.mark.asyncio
    async def test_score_readiness(self, toolkit):
        measurements = [
            PerformanceMeasurement(
                metric=PerformanceMetric.DETECTION_TIME,
                value=100.0,
                target=120.0,
                met_target=True,
            ),
            PerformanceMeasurement(
                metric=PerformanceMetric.COMMUNICATION_SPEED,
                value=2.0,
                target=3.0,
                met_target=False,
            ),
        ]
        observations = [ResponseObservation()]
        readiness = await toolkit.score_readiness(measurements, observations)
        assert isinstance(readiness, ReadinessScore)
        assert readiness.overall_score == 50.0  # 1/2 met
        assert readiness.grade == "F"  # 50% < 60
        assert len(readiness.strengths) == 1
        assert len(readiness.gaps) == 1

    @pytest.mark.asyncio
    async def test_score_readiness_all_pass(self, toolkit):
        measurements = [
            PerformanceMeasurement(
                metric=PerformanceMetric.DETECTION_TIME,
                value=90.0,
                target=120.0,
                met_target=True,
            ),
        ]
        readiness = await toolkit.score_readiness(measurements, [])
        assert readiness.overall_score == 100.0
        assert readiness.grade == "A"

    @pytest.mark.asyncio
    async def test_score_readiness_no_measurements(self, toolkit):
        readiness = await toolkit.score_readiness([], [])
        assert readiness.overall_score == 0.0
        assert readiness.grade == "F"
        assert "No measurements available" in readiness.gaps


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio
    async def test_design_scenario_node(self):
        from shieldops.agents.incident_simulator.nodes import (
            design_scenario,
            set_toolkit,
        )

        set_toolkit(IncidentSimulatorToolkit())
        state = IncidentSimulatorState(
            scenario_type=ScenarioType.RANSOMWARE,
            exercise_mode=ExerciseMode.TABLETOP,
        )
        result = await design_scenario(state)
        assert "exercise" in result
        assert isinstance(result["exercise"], ExerciseDesign)
        assert result["stage"] == SimStage.DESIGN_SCENARIO

    @pytest.mark.asyncio
    async def test_inject_events_node(self):
        from shieldops.agents.incident_simulator.nodes import (
            inject_events,
            set_toolkit,
        )

        set_toolkit(IncidentSimulatorToolkit())
        state = IncidentSimulatorState(
            scenario_type=ScenarioType.DATA_BREACH,
            exercise=ExerciseDesign(
                name="test_exercise",
                scenario_type="data_breach",
            ),
        )
        result = await inject_events(state)
        assert "injects" in result
        assert len(result["injects"]) > 0

    @pytest.mark.asyncio
    async def test_inject_events_no_exercise(self):
        from shieldops.agents.incident_simulator.nodes import (
            inject_events,
            set_toolkit,
        )

        set_toolkit(IncidentSimulatorToolkit())
        state = IncidentSimulatorState(exercise=None)
        result = await inject_events(state)
        assert result["error"] == "No exercise designed — skipping inject."

    @pytest.mark.asyncio
    async def test_observe_response_node(self):
        from shieldops.agents.incident_simulator.nodes import (
            observe_response,
            set_toolkit,
        )

        set_toolkit(IncidentSimulatorToolkit())
        state = IncidentSimulatorState(
            exercise=ExerciseDesign(name="test"),
            injects=[
                ScenarioInjection(
                    id="inj-1",
                    inject_number=1,
                    title="Test",
                ),
            ],
        )
        result = await observe_response(state)
        assert "observations" in result
        assert len(result["observations"]) == 1

    @pytest.mark.asyncio
    async def test_observe_response_no_injects(self):
        from shieldops.agents.incident_simulator.nodes import (
            observe_response,
            set_toolkit,
        )

        set_toolkit(IncidentSimulatorToolkit())
        state = IncidentSimulatorState(injects=[])
        result = await observe_response(state)
        assert result["error"] == "No injects to observe."

    @pytest.mark.asyncio
    async def test_score_performance_node(self):
        from shieldops.agents.incident_simulator.nodes import (
            score_performance,
            set_toolkit,
        )

        set_toolkit(IncidentSimulatorToolkit())
        state = IncidentSimulatorState(
            observations=[
                ResponseObservation(
                    response_time_sec=100.0,
                    communication_quality="good",
                    decision_quality="good",
                ),
            ],
        )
        result = await score_performance(state)
        assert "measurements" in result
        assert "readiness" in result
        assert result["readiness_score"] >= 0

    @pytest.mark.asyncio
    async def test_debrief_node(self):
        from shieldops.agents.incident_simulator.nodes import (
            debrief,
            set_toolkit,
        )

        set_toolkit(IncidentSimulatorToolkit())
        state = IncidentSimulatorState(
            scenario_type=ScenarioType.RANSOMWARE,
            exercise_mode=ExerciseMode.TABLETOP,
            readiness_score=75.0,
            readiness=ReadinessScore(
                grade="C",
                strengths=["Detection"],
                gaps=["Communication"],
            ),
            measurements=[
                PerformanceMeasurement(
                    metric=PerformanceMetric.DETECTION_TIME,
                    value=100.0,
                    unit="seconds",
                    target=120.0,
                    met_target=True,
                ),
            ],
        )
        result = await debrief(state)
        assert result["stage"] == SimStage.DEBRIEF

    @pytest.mark.asyncio
    async def test_report_node(self):
        from shieldops.agents.incident_simulator.nodes import (
            report,
            set_toolkit,
        )

        set_toolkit(IncidentSimulatorToolkit())
        state = IncidentSimulatorState(
            scenario_type=ScenarioType.RANSOMWARE,
            exercise_mode=ExerciseMode.TABLETOP,
            exercise=ExerciseDesign(name="test_ex"),
            readiness=ReadinessScore(grade="B"),
            readiness_score=80.0,
            injects=[ScenarioInjection(id="inj-1")],
            observations=[ResponseObservation(id="obs-1")],
            reasoning_chain=[],
        )
        result = await report(state)
        assert result["stage"] == SimStage.REPORT
        assert "report_summary" in result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class TestRunner:
    def test_runner_init(self):
        from shieldops.agents.incident_simulator.runner import (
            IncidentSimulatorRunner,
        )

        runner = IncidentSimulatorRunner()
        assert runner is not None
