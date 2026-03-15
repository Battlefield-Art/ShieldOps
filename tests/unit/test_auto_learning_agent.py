"""Tests for the Auto Learning agent."""

from __future__ import annotations

import pytest

from shieldops.agents.auto_learning.models import (
    AutoLearningState,
    BaselineMetrics,
    ExperimentOutcome,
    ExperimentResult,
    ExperimentType,
    LearningStage,
    Proposal,
    ResourceBudget,
)
from shieldops.agents.auto_learning.tools import AutoLearningToolkit


class TestAutoLearningModels:
    def test_learning_stage_values(self) -> None:
        assert LearningStage.ASSESS == "assess"
        assert LearningStage.PROPOSE == "propose"
        assert LearningStage.EXPERIMENT == "experiment"
        assert LearningStage.EVALUATE == "evaluate"
        assert LearningStage.DECIDE == "decide"

    def test_experiment_type_values(self) -> None:
        assert ExperimentType.THRESHOLD_TUNING == "threshold_tuning"
        assert ExperimentType.RUNBOOK_REFINEMENT == "runbook_refinement"

    def test_experiment_outcome_values(self) -> None:
        assert ExperimentOutcome.ACCEPTED == "accepted"
        assert ExperimentOutcome.REJECTED == "rejected"
        assert ExperimentOutcome.TIMED_OUT == "timed_out"

    def test_resource_budget_defaults(self) -> None:
        budget = ResourceBudget()
        assert budget.max_duration_seconds == 300
        assert budget.max_api_calls == 50
        assert budget.max_memory_mb == 256
        assert budget.max_concurrent == 1

    def test_baseline_metrics_defaults(self) -> None:
        metrics = BaselineMetrics()
        assert metrics.mttr_seconds == 0.0
        assert metrics.false_positive_rate == 0.0

    def test_proposal_creation(self) -> None:
        proposal = Proposal(
            id="p1",
            experiment_type=ExperimentType.THRESHOLD_TUNING,
            description="Reduce FP rate",
            target_module="alert_engine",
            expected_improvement=15.0,
        )
        assert proposal.id == "p1"
        assert proposal.risk_score == 0.0

    def test_experiment_result_defaults(self) -> None:
        result = ExperimentResult()
        assert result.outcome == ExperimentOutcome.INCONCLUSIVE
        assert result.within_budget is True
        assert result.rollback_needed is False

    def test_auto_learning_state_defaults(self) -> None:
        state = AutoLearningState()
        assert state.stage == LearningStage.ASSESS
        assert state.max_iterations == 10
        assert state.cumulative_improvement == 0.0


class TestAutoLearningToolkit:
    @pytest.mark.asyncio
    async def test_get_baseline_no_store(self) -> None:
        toolkit = AutoLearningToolkit()
        result = await toolkit.get_baseline_metrics()
        assert "mttr_seconds" in result
        assert "false_positive_rate" in result

    @pytest.mark.asyncio
    async def test_identify_areas_high_fp(self) -> None:
        toolkit = AutoLearningToolkit()
        baseline = {"false_positive_rate": 0.25, "mttr_seconds": 100}
        areas = await toolkit.identify_improvement_areas(baseline)
        assert len(areas) >= 1
        assert areas[0]["area"] == "false_positive_reduction"

    @pytest.mark.asyncio
    async def test_identify_areas_high_mttr(self) -> None:
        toolkit = AutoLearningToolkit()
        baseline = {"false_positive_rate": 0.05, "mttr_seconds": 600}
        areas = await toolkit.identify_improvement_areas(baseline)
        assert any(a["area"] == "mttr_reduction" for a in areas)

    @pytest.mark.asyncio
    async def test_identify_areas_all_good(self) -> None:
        toolkit = AutoLearningToolkit()
        baseline = {
            "false_positive_rate": 0.05,
            "mttr_seconds": 100,
            "alert_noise_ratio": 0.1,
            "resolution_accuracy": 0.95,
        }
        areas = await toolkit.identify_improvement_areas(baseline)
        assert len(areas) == 0

    @pytest.mark.asyncio
    async def test_generate_proposals(self) -> None:
        toolkit = AutoLearningToolkit()
        areas = [
            {
                "area": "false_positive_reduction",
                "current_value": 0.25,
                "target_value": 0.175,
                "experiment_type": "threshold_tuning",
                "impact": "high",
            }
        ]
        proposals = await toolkit.generate_proposals(areas)
        assert len(proposals) == 1
        assert proposals[0]["experiment_type"] == "threshold_tuning"
        assert proposals[0]["expected_improvement"] > 0

    @pytest.mark.asyncio
    async def test_run_experiment_simulation(self) -> None:
        toolkit = AutoLearningToolkit()
        proposal = {
            "id": "p1",
            "experiment_type": "threshold_tuning",
            "target_module": "alert_engine",
            "expected_improvement": 20.0,
        }
        budget = {"max_duration_seconds": 300}
        result = await toolkit.run_experiment(proposal, budget)
        assert result["within_budget"] is True
        assert "improvement_pct" in result
        assert result["outcome"] in (
            "accepted",
            "inconclusive",
            "rejected",
        )

    @pytest.mark.asyncio
    async def test_apply_change_dry_run(self) -> None:
        toolkit = AutoLearningToolkit()
        proposal = {
            "target_module": "alert_engine",
            "parameter_changes": {"threshold": 0.8},
        }
        result = await toolkit.apply_change(proposal, dry_run=True)
        assert result["applied"] is False
        assert result["dry_run"] is True

    @pytest.mark.asyncio
    async def test_rollback_change(self) -> None:
        toolkit = AutoLearningToolkit()
        proposal = {"target_module": "alert_engine"}
        result = await toolkit.rollback_change(proposal)
        assert result["rolled_back"] is True
