"""Tests for the Telemetry Optimizer Agent module.

Covers:
- TelemetryOptimizerState model creation, defaults, and field types
- TelemetryWaste model construction and validation
- OptimizationProposal model construction and field ranges
- OptimizationExperiment model construction and accept logic
- OptimizationStage enum values
- WasteCategory enum values
- OptimizationImpact enum values
- ReasoningStep model defaults
- TelemetryOptimizerToolkit methods (analyze_pipeline_costs, detect_cardinality_explosion,
  detect_over_sampling, detect_duplicate_metrics, propose_optimization,
  run_optimization_experiment, apply_optimization)
- Node functions (analyze_pipeline, identify_waste, propose_optimizations, run_experiments)
- TelemetryOptimizerRunner.run() with mocked graph
- TelemetryOptimizerRunner.get_run(), list_runs()
- TelemetryOptimizerRunner.run_continuous()
- Graph conditional routing (has_more_experiments)
- Edge cases: empty namespace, no waste, no proposals, error handling
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.agents.telemetry_optimizer.graph import has_more_experiments
from shieldops.agents.telemetry_optimizer.models import (
    OptimizationExperiment,
    OptimizationImpact,
    OptimizationProposal,
    OptimizationStage,
    ReasoningStep,
    TelemetryOptimizerState,
    TelemetryWaste,
    WasteCategory,
)
from shieldops.agents.telemetry_optimizer.nodes import (
    _get_toolkit,
    analyze_pipeline,
    identify_waste,
    propose_optimizations,
    run_experiments,
    set_toolkit,
)
from shieldops.agents.telemetry_optimizer.runner import TelemetryOptimizerRunner
from shieldops.agents.telemetry_optimizer.tools import TelemetryOptimizerToolkit

# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def reset_toolkit():
    """Reset the module-level toolkit singleton between tests."""
    import shieldops.agents.telemetry_optimizer.nodes as nodes_mod

    original = nodes_mod._toolkit
    nodes_mod._toolkit = None
    yield
    nodes_mod._toolkit = original


@pytest.fixture
def sample_waste() -> TelemetryWaste:
    return TelemetryWaste(
        service_name="api-gateway",
        waste_category=WasteCategory.HIGH_CARDINALITY,
        estimated_monthly_cost=450.0,
        data_volume_gb=120.0,
        description="Metric 'http_requests_total' has 50k unique series",
    )


@pytest.fixture
def sample_proposal() -> OptimizationProposal:
    return OptimizationProposal(
        id="opt-abc123",
        waste_category=WasteCategory.HIGH_CARDINALITY,
        target_service="api-gateway",
        action="Drop high-cardinality labels on api-gateway to reduce series count",
        estimated_savings_pct=35.0,
        risk="medium",
        reversible=True,
    )


@pytest.fixture
def sample_experiment() -> OptimizationExperiment:
    return OptimizationExperiment(
        proposal_id="opt-abc123",
        baseline_cost=100.0,
        experiment_cost=65.0,
        savings_pct=35.0,
        observability_impact="none",
        accepted=True,
    )


@pytest.fixture
def base_state() -> TelemetryOptimizerState:
    return TelemetryOptimizerState(
        request_id="topt-test001",
        target_namespace="production",
    )


@pytest.fixture
def state_with_waste(sample_waste: TelemetryWaste) -> TelemetryOptimizerState:
    return TelemetryOptimizerState(
        request_id="topt-test002",
        target_namespace="production",
        waste_items=[sample_waste],
        pipeline_costs={
            "namespace": "production",
            "services": {"api-gateway": {"monthly_cost": 500.0}},
            "total_monthly_cost": 500.0,
            "total_data_volume_gb": 200.0,
        },
    )


@pytest.fixture
def state_with_proposals(
    sample_waste: TelemetryWaste,
    sample_proposal: OptimizationProposal,
) -> TelemetryOptimizerState:
    return TelemetryOptimizerState(
        request_id="topt-test003",
        target_namespace="production",
        waste_items=[sample_waste],
        proposals=[sample_proposal],
    )


# ── Enum Tests ───────────────────────────────────────────────────


class TestOptimizationStage:
    def test_all_stages_exist(self):
        assert OptimizationStage.ANALYZE == "analyze"
        assert OptimizationStage.IDENTIFY_WASTE == "identify_waste"
        assert OptimizationStage.PROPOSE == "propose"
        assert OptimizationStage.EXPERIMENT == "experiment"
        assert OptimizationStage.APPLY == "apply"

    def test_stage_count(self):
        assert len(OptimizationStage) == 5


class TestWasteCategory:
    def test_all_categories_exist(self):
        assert WasteCategory.HIGH_CARDINALITY == "high_cardinality"
        assert WasteCategory.OVER_SAMPLING == "over_sampling"
        assert WasteCategory.DUPLICATE_METRICS == "duplicate_metrics"
        assert WasteCategory.UNUSED_DASHBOARDS == "unused_dashboards"
        assert WasteCategory.STALE_ALERTS == "stale_alerts"

    def test_category_count(self):
        assert len(WasteCategory) == 5


class TestOptimizationImpact:
    def test_all_impacts_exist(self):
        assert OptimizationImpact.HIGH_SAVINGS == "high_savings"
        assert OptimizationImpact.MODERATE_SAVINGS == "moderate_savings"
        assert OptimizationImpact.LOW_SAVINGS == "low_savings"
        assert OptimizationImpact.NO_IMPACT == "no_impact"

    def test_impact_count(self):
        assert len(OptimizationImpact) == 4


# ── Model Tests ──────────────────────────────────────────────────


class TestTelemetryWaste:
    def test_creation(self, sample_waste: TelemetryWaste):
        assert sample_waste.service_name == "api-gateway"
        assert sample_waste.waste_category == WasteCategory.HIGH_CARDINALITY
        assert sample_waste.estimated_monthly_cost == 450.0
        assert sample_waste.data_volume_gb == 120.0

    def test_cost_must_be_non_negative(self):
        with pytest.raises(ValueError):
            TelemetryWaste(
                service_name="svc",
                waste_category=WasteCategory.OVER_SAMPLING,
                estimated_monthly_cost=-10.0,
                data_volume_gb=1.0,
                description="test",
            )

    def test_volume_must_be_non_negative(self):
        with pytest.raises(ValueError):
            TelemetryWaste(
                service_name="svc",
                waste_category=WasteCategory.OVER_SAMPLING,
                estimated_monthly_cost=10.0,
                data_volume_gb=-1.0,
                description="test",
            )


class TestOptimizationProposal:
    def test_creation(self, sample_proposal: OptimizationProposal):
        assert sample_proposal.id == "opt-abc123"
        assert sample_proposal.waste_category == WasteCategory.HIGH_CARDINALITY
        assert sample_proposal.target_service == "api-gateway"
        assert sample_proposal.estimated_savings_pct == 35.0
        assert sample_proposal.reversible is True

    def test_savings_pct_range(self):
        with pytest.raises(ValueError):
            OptimizationProposal(
                id="test",
                waste_category=WasteCategory.OVER_SAMPLING,
                target_service="svc",
                action="test",
                estimated_savings_pct=150.0,
            )

    def test_savings_pct_non_negative(self):
        with pytest.raises(ValueError):
            OptimizationProposal(
                id="test",
                waste_category=WasteCategory.OVER_SAMPLING,
                target_service="svc",
                action="test",
                estimated_savings_pct=-5.0,
            )


class TestOptimizationExperiment:
    def test_creation(self, sample_experiment: OptimizationExperiment):
        assert sample_experiment.proposal_id == "opt-abc123"
        assert sample_experiment.baseline_cost == 100.0
        assert sample_experiment.experiment_cost == 65.0
        assert sample_experiment.savings_pct == 35.0
        assert sample_experiment.accepted is True

    def test_defaults(self):
        exp = OptimizationExperiment(proposal_id="test")
        assert exp.baseline_cost == 0.0
        assert exp.experiment_cost == 0.0
        assert exp.savings_pct == 0.0
        assert exp.observability_impact == "none"
        assert exp.accepted is False


class TestReasoningStep:
    def test_creation(self):
        step = ReasoningStep(
            step_number=1,
            action="analyze_pipeline",
            input_summary="test input",
            output_summary="test output",
        )
        assert step.step_number == 1
        assert step.duration_ms == 0
        assert step.tool_used is None


class TestTelemetryOptimizerState:
    def test_defaults(self, base_state: TelemetryOptimizerState):
        assert base_state.request_id == "topt-test001"
        assert base_state.stage == OptimizationStage.ANALYZE
        assert base_state.target_namespace == "production"
        assert base_state.waste_items == []
        assert base_state.proposals == []
        assert base_state.experiments == []
        assert base_state.total_savings_pct == 0.0
        assert base_state.budget_seconds == 300
        assert base_state.confidence_score == 0.0
        assert base_state.reasoning_chain == []
        assert base_state.current_step == "init"
        assert base_state.error is None
        assert base_state.pipeline_costs == {}

    def test_state_with_waste(self, state_with_waste: TelemetryOptimizerState):
        assert len(state_with_waste.waste_items) == 1
        assert state_with_waste.pipeline_costs["total_monthly_cost"] == 500.0


# ── Toolkit Tests ────────────────────────────────────────────────


class TestTelemetryOptimizerToolkit:
    @pytest.mark.asyncio
    async def test_analyze_pipeline_costs_no_backend(self):
        toolkit = TelemetryOptimizerToolkit()
        result = await toolkit.analyze_pipeline_costs("production")
        assert result["namespace"] == "production"
        assert result["total_monthly_cost"] == 0.0
        assert result["total_data_volume_gb"] == 0.0

    @pytest.mark.asyncio
    async def test_analyze_pipeline_costs_with_backend(self):
        cost_api = AsyncMock()
        cost_api.get_namespace_costs.return_value = {
            "namespace": "production",
            "services": {"svc-a": {"cost": 100}},
            "total_monthly_cost": 100.0,
            "total_data_volume_gb": 50.0,
        }
        toolkit = TelemetryOptimizerToolkit(cost_api=cost_api)
        result = await toolkit.analyze_pipeline_costs("production")
        assert result["total_monthly_cost"] == 100.0
        cost_api.get_namespace_costs.assert_awaited_once_with("production")

    @pytest.mark.asyncio
    async def test_analyze_pipeline_costs_backend_error(self):
        cost_api = AsyncMock()
        cost_api.get_namespace_costs.side_effect = RuntimeError("connection failed")
        toolkit = TelemetryOptimizerToolkit(cost_api=cost_api)
        result = await toolkit.analyze_pipeline_costs("production")
        # Falls back to empty structure
        assert result["total_monthly_cost"] == 0.0

    @pytest.mark.asyncio
    async def test_detect_cardinality_explosion_no_backend(self):
        toolkit = TelemetryOptimizerToolkit()
        result = await toolkit.detect_cardinality_explosion("svc-a")
        assert result == []

    @pytest.mark.asyncio
    async def test_detect_cardinality_explosion_with_backend(self):
        metrics = AsyncMock()
        metrics.get_high_cardinality_metrics.return_value = [
            {"metric": "http_requests", "series_count": 50000}
        ]
        toolkit = TelemetryOptimizerToolkit(metrics_backend=metrics)
        result = await toolkit.detect_cardinality_explosion("svc-a")
        assert len(result) == 1
        assert result[0]["series_count"] == 50000

    @pytest.mark.asyncio
    async def test_detect_over_sampling_no_backend(self):
        toolkit = TelemetryOptimizerToolkit()
        result = await toolkit.detect_over_sampling("svc-a")
        assert result == []

    @pytest.mark.asyncio
    async def test_detect_over_sampling_with_backend(self):
        metrics = AsyncMock()
        metrics.get_sampling_analysis.return_value = [
            {"actual_rate": "100%", "recommended_rate": "10%"}
        ]
        toolkit = TelemetryOptimizerToolkit(metrics_backend=metrics)
        result = await toolkit.detect_over_sampling("svc-a")
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_detect_duplicate_metrics_no_backend(self):
        toolkit = TelemetryOptimizerToolkit()
        result = await toolkit.detect_duplicate_metrics("production")
        assert result == []

    @pytest.mark.asyncio
    async def test_detect_duplicate_metrics_with_backend(self):
        metrics = AsyncMock()
        metrics.find_duplicate_metrics.return_value = [
            {"metrics": ["cpu_a", "cpu_b"], "sources": ["prom", "dd"]}
        ]
        toolkit = TelemetryOptimizerToolkit(metrics_backend=metrics)
        result = await toolkit.detect_duplicate_metrics("production")
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_propose_optimization(self, sample_waste: TelemetryWaste):
        toolkit = TelemetryOptimizerToolkit()
        proposal = await toolkit.propose_optimization(sample_waste)
        assert proposal.waste_category == WasteCategory.HIGH_CARDINALITY
        assert proposal.target_service == "api-gateway"
        assert proposal.reversible is True
        assert proposal.risk == "medium"
        assert proposal.id.startswith("opt-")

    @pytest.mark.asyncio
    async def test_propose_optimization_all_categories(self):
        toolkit = TelemetryOptimizerToolkit()
        for category in WasteCategory:
            waste = TelemetryWaste(
                service_name="test-svc",
                waste_category=category,
                estimated_monthly_cost=100.0,
                data_volume_gb=50.0,
                description=f"Test {category}",
            )
            proposal = await toolkit.propose_optimization(waste)
            assert proposal.waste_category == category
            assert proposal.estimated_savings_pct >= 0.0
            assert proposal.estimated_savings_pct <= 100.0

    @pytest.mark.asyncio
    async def test_run_experiment_no_backend(self, sample_proposal: OptimizationProposal):
        toolkit = TelemetryOptimizerToolkit()
        experiment = await toolkit.run_optimization_experiment(sample_proposal)
        assert experiment.proposal_id == "opt-abc123"
        assert experiment.baseline_cost == 100.0
        assert experiment.experiment_cost == 100.0
        assert experiment.savings_pct == 0.0
        assert experiment.accepted is False

    @pytest.mark.asyncio
    async def test_run_experiment_with_savings(self, sample_proposal: OptimizationProposal):
        cost_api = AsyncMock()
        cost_api.measure_cost.side_effect = [
            {"cost": 100.0},  # baseline
            {"cost": 60.0},  # experiment
        ]
        cost_api.apply_shadow.return_value = None
        cost_api.rollback_shadow.return_value = None

        toolkit = TelemetryOptimizerToolkit(cost_api=cost_api)
        experiment = await toolkit.run_optimization_experiment(sample_proposal)
        assert experiment.savings_pct == 40.0
        assert experiment.accepted is True

    @pytest.mark.asyncio
    async def test_apply_optimization_dry_run(self, sample_proposal: OptimizationProposal):
        toolkit = TelemetryOptimizerToolkit()
        result = await toolkit.apply_optimization(sample_proposal, dry_run=True)
        assert result["status"] == "simulated"
        assert result["dry_run"] is True

    @pytest.mark.asyncio
    async def test_apply_optimization_live(self, sample_proposal: OptimizationProposal):
        cost_api = AsyncMock()
        cost_api.apply_optimization.return_value = {"status": "applied"}
        toolkit = TelemetryOptimizerToolkit(cost_api=cost_api)
        result = await toolkit.apply_optimization(sample_proposal, dry_run=False)
        assert result["status"] == "applied"

    @pytest.mark.asyncio
    async def test_apply_optimization_live_error(self, sample_proposal: OptimizationProposal):
        cost_api = AsyncMock()
        cost_api.apply_optimization.side_effect = RuntimeError("apply failed")
        toolkit = TelemetryOptimizerToolkit(cost_api=cost_api)
        result = await toolkit.apply_optimization(sample_proposal, dry_run=False)
        assert result["status"] == "failed"
        assert "apply failed" in result["error"]


# ── Node Tests ───────────────────────────────────────────────────


class TestNodes:
    @pytest.mark.asyncio
    async def test_analyze_pipeline_node(self, base_state: TelemetryOptimizerState):
        result = await analyze_pipeline(base_state)
        assert result["current_step"] == "analyze_pipeline"
        assert result["stage"] == OptimizationStage.IDENTIFY_WASTE
        assert len(result["reasoning_chain"]) == 1
        assert result["reasoning_chain"][0].action == "analyze_pipeline"
        assert "pipeline_costs" in result

    @pytest.mark.asyncio
    async def test_identify_waste_node_no_services(self, base_state: TelemetryOptimizerState):
        result = await identify_waste(base_state)
        assert result["current_step"] == "identify_waste"
        assert result["stage"] == OptimizationStage.PROPOSE
        assert isinstance(result["waste_items"], list)

    @pytest.mark.asyncio
    async def test_identify_waste_node_with_services(
        self, state_with_waste: TelemetryOptimizerState
    ):
        result = await identify_waste(state_with_waste)
        assert result["current_step"] == "identify_waste"
        assert isinstance(result["waste_items"], list)

    @pytest.mark.asyncio
    async def test_propose_optimizations_node(self, state_with_waste: TelemetryOptimizerState):
        result = await propose_optimizations(state_with_waste)
        assert result["current_step"] == "propose_optimizations"
        assert result["stage"] == OptimizationStage.EXPERIMENT
        assert len(result["proposals"]) == len(state_with_waste.waste_items)

    @pytest.mark.asyncio
    async def test_propose_optimizations_no_waste(self, base_state: TelemetryOptimizerState):
        result = await propose_optimizations(base_state)
        assert result["proposals"] == []

    @pytest.mark.asyncio
    async def test_run_experiments_node(self, state_with_proposals: TelemetryOptimizerState):
        result = await run_experiments(state_with_proposals)
        assert result["current_step"] == "run_experiments"
        assert result["stage"] == OptimizationStage.APPLY
        assert len(result["experiments"]) == len(state_with_proposals.proposals)

    @pytest.mark.asyncio
    async def test_run_experiments_no_proposals(self, base_state: TelemetryOptimizerState):
        result = await run_experiments(base_state)
        assert result["experiments"] == []
        assert result["total_savings_pct"] == 0.0

    @pytest.mark.asyncio
    async def test_get_toolkit_returns_empty_when_not_set(self):
        toolkit = _get_toolkit()
        assert isinstance(toolkit, TelemetryOptimizerToolkit)

    @pytest.mark.asyncio
    async def test_set_toolkit_persists(self):
        custom_toolkit = TelemetryOptimizerToolkit()
        set_toolkit(custom_toolkit)
        assert _get_toolkit() is custom_toolkit


# ── Graph Routing Tests ──────────────────────────────────────────


class TestGraphRouting:
    def test_has_more_experiments_ends_when_no_remaining_waste(
        self, sample_waste: TelemetryWaste, sample_proposal: OptimizationProposal
    ):
        state = TelemetryOptimizerState(
            request_id="test",
            target_namespace="production",
            waste_items=[sample_waste],
            proposals=[sample_proposal],
            confidence_score=0.9,
        )
        assert has_more_experiments(state) == "__end__"

    def test_has_more_experiments_loops_when_remaining_waste(self):
        waste_a = TelemetryWaste(
            service_name="svc-a",
            waste_category=WasteCategory.HIGH_CARDINALITY,
            estimated_monthly_cost=100.0,
            data_volume_gb=50.0,
            description="test",
        )
        waste_b = TelemetryWaste(
            service_name="svc-b",
            waste_category=WasteCategory.OVER_SAMPLING,
            estimated_monthly_cost=200.0,
            data_volume_gb=80.0,
            description="test",
        )
        proposal_a = OptimizationProposal(
            id="opt-a",
            waste_category=WasteCategory.HIGH_CARDINALITY,
            target_service="svc-a",
            action="test",
            estimated_savings_pct=30.0,
        )
        state = TelemetryOptimizerState(
            request_id="test",
            target_namespace="production",
            waste_items=[waste_a, waste_b],
            proposals=[proposal_a],
            confidence_score=0.5,
        )
        assert has_more_experiments(state) == "propose_optimizations"

    def test_has_more_experiments_ends_when_high_confidence(self):
        waste_a = TelemetryWaste(
            service_name="svc-a",
            waste_category=WasteCategory.HIGH_CARDINALITY,
            estimated_monthly_cost=100.0,
            data_volume_gb=50.0,
            description="test",
        )
        waste_b = TelemetryWaste(
            service_name="svc-b",
            waste_category=WasteCategory.OVER_SAMPLING,
            estimated_monthly_cost=200.0,
            data_volume_gb=80.0,
            description="test",
        )
        proposal_a = OptimizationProposal(
            id="opt-a",
            waste_category=WasteCategory.HIGH_CARDINALITY,
            target_service="svc-a",
            action="test",
            estimated_savings_pct=30.0,
        )
        state = TelemetryOptimizerState(
            request_id="test",
            target_namespace="production",
            waste_items=[waste_a, waste_b],
            proposals=[proposal_a],
            confidence_score=0.85,
        )
        assert has_more_experiments(state) == "__end__"


# ── Runner Tests ─────────────────────────────────────────────────


class TestTelemetryOptimizerRunner:
    @pytest.mark.asyncio
    async def test_run_returns_state(self):
        with patch(
            "shieldops.agents.telemetry_optimizer.runner.create_telemetry_optimizer_graph"
        ) as mock_graph:
            mock_compiled = MagicMock()
            mock_compiled.ainvoke = AsyncMock(
                return_value=TelemetryOptimizerState(
                    request_id="topt-mock",
                    target_namespace="production",
                    current_step="run_experiments",
                    total_savings_pct=25.0,
                    confidence_score=0.8,
                ).model_dump()
            )
            mock_graph.return_value.compile.return_value = mock_compiled

            runner = TelemetryOptimizerRunner()
            result = await runner.run("production")
            assert result.target_namespace == "production"
            assert result.total_savings_pct == 25.0

    @pytest.mark.asyncio
    async def test_run_handles_error(self):
        with patch(
            "shieldops.agents.telemetry_optimizer.runner.create_telemetry_optimizer_graph"
        ) as mock_graph:
            mock_compiled = MagicMock()
            mock_compiled.ainvoke = AsyncMock(side_effect=RuntimeError("graph failed"))
            mock_graph.return_value.compile.return_value = mock_compiled

            runner = TelemetryOptimizerRunner()
            result = await runner.run("production")
            assert result.error == "graph failed"
            assert result.current_step == "failed"

    @pytest.mark.asyncio
    async def test_get_run(self):
        with patch(
            "shieldops.agents.telemetry_optimizer.runner.create_telemetry_optimizer_graph"
        ) as mock_graph:
            mock_compiled = MagicMock()
            mock_compiled.ainvoke = AsyncMock(
                return_value=TelemetryOptimizerState(
                    request_id="topt-lookup",
                    target_namespace="staging",
                    current_step="complete",
                ).model_dump()
            )
            mock_graph.return_value.compile.return_value = mock_compiled

            runner = TelemetryOptimizerRunner()
            await runner.run("staging")
            # Request ID is generated internally, get it from the stored runs
            runs = runner.list_runs()
            assert len(runs) == 1
            stored = runner.get_run(runs[0]["request_id"])
            assert stored is not None

    @pytest.mark.asyncio
    async def test_list_runs(self):
        with patch(
            "shieldops.agents.telemetry_optimizer.runner.create_telemetry_optimizer_graph"
        ) as mock_graph:
            mock_compiled = MagicMock()
            mock_compiled.ainvoke = AsyncMock(
                return_value=TelemetryOptimizerState(
                    request_id="topt-list",
                    target_namespace="prod",
                    current_step="complete",
                ).model_dump()
            )
            mock_graph.return_value.compile.return_value = mock_compiled

            runner = TelemetryOptimizerRunner()
            await runner.run("prod")
            runs = runner.list_runs()
            assert len(runs) == 1
            assert runs[0]["namespace"] == "prod"

    @pytest.mark.asyncio
    async def test_get_run_not_found(self):
        with patch(
            "shieldops.agents.telemetry_optimizer.runner.create_telemetry_optimizer_graph"
        ) as mock_graph:
            mock_graph.return_value.compile.return_value = MagicMock()
            runner = TelemetryOptimizerRunner()
            assert runner.get_run("nonexistent") is None

    @pytest.mark.asyncio
    async def test_run_continuous_stops_on_no_waste(self):
        with patch(
            "shieldops.agents.telemetry_optimizer.runner.create_telemetry_optimizer_graph"
        ) as mock_graph:
            mock_compiled = MagicMock()
            mock_compiled.ainvoke = AsyncMock(
                return_value=TelemetryOptimizerState(
                    request_id="topt-cont",
                    target_namespace="prod",
                    waste_items=[],
                    current_step="complete",
                ).model_dump()
            )
            mock_graph.return_value.compile.return_value = mock_compiled

            runner = TelemetryOptimizerRunner()
            results = await runner.run_continuous("prod", max_iterations=5)
            assert len(results) == 1

    @pytest.mark.asyncio
    async def test_run_continuous_stops_on_high_confidence(self):
        call_count = 0

        async def mock_invoke(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return TelemetryOptimizerState(
                request_id=f"topt-{call_count}",
                target_namespace="prod",
                waste_items=[
                    TelemetryWaste(
                        service_name="svc",
                        waste_category=WasteCategory.HIGH_CARDINALITY,
                        estimated_monthly_cost=100.0,
                        data_volume_gb=50.0,
                        description="test",
                    )
                ],
                confidence_score=0.95,
                current_step="complete",
            ).model_dump()

        with patch(
            "shieldops.agents.telemetry_optimizer.runner.create_telemetry_optimizer_graph"
        ) as mock_graph:
            mock_compiled = MagicMock()
            mock_compiled.ainvoke = AsyncMock(side_effect=mock_invoke)
            mock_graph.return_value.compile.return_value = mock_compiled

            runner = TelemetryOptimizerRunner()
            results = await runner.run_continuous("prod", max_iterations=10)
            assert len(results) == 1  # Stops after first iteration due to high confidence

    @pytest.mark.asyncio
    async def test_run_continuous_stops_on_error(self):
        with patch(
            "shieldops.agents.telemetry_optimizer.runner.create_telemetry_optimizer_graph"
        ) as mock_graph:
            mock_compiled = MagicMock()
            mock_compiled.ainvoke = AsyncMock(side_effect=RuntimeError("fail"))
            mock_graph.return_value.compile.return_value = mock_compiled

            runner = TelemetryOptimizerRunner()
            results = await runner.run_continuous("prod", max_iterations=5)
            assert len(results) == 1
            assert results[0].error is not None
