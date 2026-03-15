"""Tests for auto-learning engine modules —
ExperimentLifecycleEngine, ResourceBudgetTrackerEngine, ConvergenceOptimizerEngine."""

from __future__ import annotations

from shieldops.analytics.convergence_optimizer_engine import (
    ConvergenceOptimizerAnalysis,
    ConvergenceOptimizerEngine,
    ConvergenceOptimizerRecord,
    ConvergenceOptimizerReport,
    ConvergencePhase,
    LearningRateStrategy,
    OptimizationAction,
)
from shieldops.analytics.experiment_lifecycle_engine import (
    BudgetStatus,
    ExperimentDomain,
    ExperimentLifecycleAnalysis,
    ExperimentLifecycleEngine,
    ExperimentLifecycleRecord,
    ExperimentLifecycleReport,
    ExperimentPhase,
)
from shieldops.analytics.resource_budget_tracker_engine import (
    BudgetCompliance,
    ConsumerType,
    ResourceBudgetAnalysis,
    ResourceBudgetRecord,
    ResourceBudgetReport,
    ResourceBudgetTrackerEngine,
    ResourceType,
)

# ===========================================================================
# ExperimentLifecycleEngine
# ===========================================================================


def _exp_engine(**kw: object) -> ExperimentLifecycleEngine:
    return ExperimentLifecycleEngine(**kw)


class TestExperimentLifecycleEnums:
    def test_phase_proposed(self) -> None:
        assert ExperimentPhase.PROPOSED == "proposed"

    def test_phase_running(self) -> None:
        assert ExperimentPhase.RUNNING == "running"

    def test_phase_completed(self) -> None:
        assert ExperimentPhase.COMPLETED == "completed"

    def test_phase_accepted(self) -> None:
        assert ExperimentPhase.ACCEPTED == "accepted"

    def test_phase_rejected(self) -> None:
        assert ExperimentPhase.REJECTED == "rejected"

    def test_domain_alert_tuning(self) -> None:
        assert ExperimentDomain.ALERT_TUNING == "alert_tuning"

    def test_domain_routing(self) -> None:
        assert ExperimentDomain.ROUTING == "routing"

    def test_domain_runbook(self) -> None:
        assert ExperimentDomain.RUNBOOK == "runbook"

    def test_domain_policy(self) -> None:
        assert ExperimentDomain.POLICY == "policy"

    def test_domain_threshold(self) -> None:
        assert ExperimentDomain.THRESHOLD == "threshold"

    def test_budget_within(self) -> None:
        assert BudgetStatus.WITHIN_BUDGET == "within_budget"

    def test_budget_approaching(self) -> None:
        assert BudgetStatus.APPROACHING_LIMIT == "approaching_limit"

    def test_budget_exceeded(self) -> None:
        assert BudgetStatus.EXCEEDED == "exceeded"

    def test_budget_not_set(self) -> None:
        assert BudgetStatus.NOT_SET == "not_set"


class TestExperimentLifecycleModels:
    def test_record_defaults(self) -> None:
        r = ExperimentLifecycleRecord()
        assert r.id
        assert r.experiment_id == ""
        assert r.experiment_phase == ExperimentPhase.PROPOSED
        assert r.experiment_domain == ExperimentDomain.ALERT_TUNING
        assert r.budget_status == BudgetStatus.NOT_SET
        assert r.metric_before == 0.0
        assert r.metric_after == 0.0
        assert r.improvement_pct == 0.0

    def test_analysis_defaults(self) -> None:
        a = ExperimentLifecycleAnalysis()
        assert a.id
        assert a.experiment_id == ""
        assert a.acceptance_rate == 0.0

    def test_report_defaults(self) -> None:
        rpt = ExperimentLifecycleReport()
        assert rpt.id
        assert rpt.total_records == 0
        assert rpt.overall_acceptance_rate == 0.0
        assert rpt.recommendations == []


class TestExperimentLifecycleEngine:
    def test_add_record(self) -> None:
        eng = _exp_engine()
        rec = eng.add_record(experiment_id="exp-1", experiment_phase=ExperimentPhase.PROPOSED)
        assert rec.experiment_id == "exp-1"
        assert rec.experiment_phase == ExperimentPhase.PROPOSED

    def test_ring_buffer_eviction(self) -> None:
        eng = _exp_engine(max_records=3)
        for i in range(5):
            eng.add_record(experiment_id=f"exp-{i}")
        stats = eng.get_stats()
        assert stats["total_records"] == 3

    def test_process_found(self) -> None:
        eng = _exp_engine()
        rec = eng.add_record(
            experiment_id="exp-1",
            experiment_phase=ExperimentPhase.ACCEPTED,
            improvement_pct=12.5,
        )
        result = eng.process(rec.id)
        assert isinstance(result, ExperimentLifecycleAnalysis)
        assert result.experiment_id == "exp-1"

    def test_process_not_found(self) -> None:
        eng = _exp_engine()
        result = eng.process("nonexistent")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"

    def test_generate_report_with_data(self) -> None:
        eng = _exp_engine()
        eng.add_record(
            experiment_id="exp-1",
            experiment_phase=ExperimentPhase.ACCEPTED,
            experiment_domain=ExperimentDomain.ALERT_TUNING,
            improvement_pct=15.0,
        )
        eng.add_record(
            experiment_id="exp-2",
            experiment_phase=ExperimentPhase.REJECTED,
            experiment_domain=ExperimentDomain.ROUTING,
        )
        report = eng.generate_report()
        assert isinstance(report, ExperimentLifecycleReport)
        assert report.total_records == 2
        assert report.overall_acceptance_rate == 0.5
        assert "accepted" in report.by_experiment_phase

    def test_get_stats(self) -> None:
        eng = _exp_engine()
        eng.add_record(experiment_id="exp-1")
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert "phase_distribution" in stats

    def test_clear_data(self) -> None:
        eng = _exp_engine()
        eng.add_record(experiment_id="exp-1")
        result = eng.clear_data()
        assert result["status"] == "cleared"
        assert eng.get_stats()["total_records"] == 0

    def test_compute_acceptance_rate_all(self) -> None:
        eng = _exp_engine()
        eng.add_record(experiment_id="e1", experiment_phase=ExperimentPhase.ACCEPTED)
        eng.add_record(experiment_id="e2", experiment_phase=ExperimentPhase.REJECTED)
        eng.add_record(experiment_id="e3", experiment_phase=ExperimentPhase.ACCEPTED)
        result = eng.compute_acceptance_rate()
        assert result["domain"] == "all"
        assert result["accepted"] == 2
        assert result["rejected"] == 1
        assert abs(result["acceptance_rate"] - 0.6667) < 0.01

    def test_compute_acceptance_rate_by_domain(self) -> None:
        eng = _exp_engine()
        eng.add_record(
            experiment_id="e1",
            experiment_phase=ExperimentPhase.ACCEPTED,
            experiment_domain=ExperimentDomain.RUNBOOK,
        )
        eng.add_record(
            experiment_id="e2",
            experiment_phase=ExperimentPhase.REJECTED,
            experiment_domain=ExperimentDomain.ROUTING,
        )
        result = eng.compute_acceptance_rate(domain=ExperimentDomain.RUNBOOK)
        assert result["domain"] == "runbook"
        assert result["accepted"] == 1
        assert result["acceptance_rate"] == 1.0

    def test_identify_diminishing_returns(self) -> None:
        eng = _exp_engine()
        # Early high improvement, late low improvement
        for i in range(8):
            imp = 20.0 if i < 4 else 2.0
            eng.add_record(experiment_id="exp-dr", improvement_pct=imp)
        results = eng.identify_diminishing_returns()
        assert len(results) >= 1
        assert results[0]["experiment_id"] == "exp-dr"
        assert results[0]["avg_late_improvement"] < results[0]["avg_early_improvement"]

    def test_identify_diminishing_returns_insufficient_data(self) -> None:
        eng = _exp_engine()
        eng.add_record(experiment_id="exp-x", improvement_pct=10.0)
        results = eng.identify_diminishing_returns()
        assert results == []

    def test_recommend_experiment_focus(self) -> None:
        eng = _exp_engine()
        eng.add_record(
            experiment_id="e1",
            experiment_phase=ExperimentPhase.ACCEPTED,
            experiment_domain=ExperimentDomain.ALERT_TUNING,
            improvement_pct=30.0,
        )
        eng.add_record(
            experiment_id="e2",
            experiment_phase=ExperimentPhase.REJECTED,
            experiment_domain=ExperimentDomain.ROUTING,
            improvement_pct=2.0,
        )
        results = eng.recommend_experiment_focus()
        assert len(results) == 2
        # Alert tuning should rank higher
        assert results[0]["domain"] == "alert_tuning"
        assert results[0]["focus_score"] > results[1]["focus_score"]

    def test_recommend_experiment_focus_empty(self) -> None:
        eng = _exp_engine()
        assert eng.recommend_experiment_focus() == []

    def test_generate_report_empty(self) -> None:
        eng = _exp_engine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert "healthy" in report.recommendations[0]


# ===========================================================================
# ResourceBudgetTrackerEngine
# ===========================================================================


def _budget_engine(**kw: object) -> ResourceBudgetTrackerEngine:
    return ResourceBudgetTrackerEngine(**kw)


class TestResourceBudgetEnums:
    def test_resource_cpu(self) -> None:
        assert ResourceType.CPU_SECONDS == "cpu_seconds"

    def test_resource_memory(self) -> None:
        assert ResourceType.MEMORY_MB == "memory_mb"

    def test_resource_api_calls(self) -> None:
        assert ResourceType.API_CALLS == "api_calls"

    def test_resource_wall_clock(self) -> None:
        assert ResourceType.WALL_CLOCK_SECONDS == "wall_clock_seconds"

    def test_compliance_compliant(self) -> None:
        assert BudgetCompliance.COMPLIANT == "compliant"

    def test_compliance_warning(self) -> None:
        assert BudgetCompliance.WARNING == "warning"

    def test_compliance_exceeded(self) -> None:
        assert BudgetCompliance.EXCEEDED == "exceeded"

    def test_compliance_unknown(self) -> None:
        assert BudgetCompliance.UNKNOWN == "unknown"

    def test_consumer_agent(self) -> None:
        assert ConsumerType.AGENT == "agent"

    def test_consumer_experiment(self) -> None:
        assert ConsumerType.EXPERIMENT == "experiment"

    def test_consumer_pipeline(self) -> None:
        assert ConsumerType.PIPELINE == "pipeline"

    def test_consumer_scheduled_job(self) -> None:
        assert ConsumerType.SCHEDULED_JOB == "scheduled_job"


class TestResourceBudgetModels:
    def test_record_defaults(self) -> None:
        r = ResourceBudgetRecord()
        assert r.id
        assert r.consumer_id == ""
        assert r.consumer_type == ConsumerType.AGENT
        assert r.resource_type == ResourceType.CPU_SECONDS
        assert r.allocated == 0.0
        assert r.consumed == 0.0

    def test_analysis_defaults(self) -> None:
        a = ResourceBudgetAnalysis()
        assert a.id
        assert a.total_consumed == 0.0
        assert a.budget_compliance == BudgetCompliance.UNKNOWN

    def test_report_defaults(self) -> None:
        rpt = ResourceBudgetReport()
        assert rpt.id
        assert rpt.total_records == 0
        assert rpt.over_budget_consumers == []


class TestResourceBudgetTrackerEngine:
    def test_add_record(self) -> None:
        eng = _budget_engine()
        rec = eng.add_record(
            consumer_id="agent-1",
            resource_type=ResourceType.CPU_SECONDS,
            allocated=100.0,
            consumed=50.0,
        )
        assert rec.consumer_id == "agent-1"
        assert rec.allocated == 100.0

    def test_ring_buffer_eviction(self) -> None:
        eng = _budget_engine(max_records=3)
        for i in range(5):
            eng.add_record(consumer_id=f"c-{i}")
        assert eng.get_stats()["total_records"] == 3

    def test_process_found(self) -> None:
        eng = _budget_engine()
        rec = eng.add_record(
            consumer_id="agent-1",
            allocated=100.0,
            consumed=85.0,
        )
        result = eng.process(rec.id)
        assert isinstance(result, ResourceBudgetAnalysis)
        assert result.consumer_id == "agent-1"
        assert result.budget_compliance == BudgetCompliance.WARNING

    def test_process_not_found(self) -> None:
        eng = _budget_engine()
        result = eng.process("nonexistent")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"

    def test_generate_report_with_data(self) -> None:
        eng = _budget_engine()
        eng.add_record(
            consumer_id="a1",
            resource_type=ResourceType.CPU_SECONDS,
            budget_compliance=BudgetCompliance.COMPLIANT,
            allocated=100.0,
            consumed=50.0,
            utilization_pct=50.0,
        )
        eng.add_record(
            consumer_id="a2",
            resource_type=ResourceType.MEMORY_MB,
            budget_compliance=BudgetCompliance.EXCEEDED,
            allocated=100.0,
            consumed=120.0,
            utilization_pct=120.0,
        )
        report = eng.generate_report()
        assert isinstance(report, ResourceBudgetReport)
        assert report.total_records == 2
        assert report.avg_utilization_pct == 85.0
        assert "a2" in report.over_budget_consumers

    def test_get_stats(self) -> None:
        eng = _budget_engine()
        eng.add_record(consumer_id="a1", resource_type=ResourceType.API_CALLS)
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert "resource_type_distribution" in stats

    def test_clear_data(self) -> None:
        eng = _budget_engine()
        eng.add_record(consumer_id="a1")
        result = eng.clear_data()
        assert result["status"] == "cleared"
        assert eng.get_stats()["total_records"] == 0

    def test_identify_over_budget_consumers(self) -> None:
        eng = _budget_engine()
        eng.add_record(consumer_id="a1", allocated=100.0, consumed=150.0)
        eng.add_record(consumer_id="a2", allocated=100.0, consumed=50.0)
        results = eng.identify_over_budget_consumers()
        assert len(results) == 1
        assert results[0]["consumer_id"] == "a1"
        assert results[0]["overage_pct"] == 50.0

    def test_identify_over_budget_empty(self) -> None:
        eng = _budget_engine()
        eng.add_record(consumer_id="a1", allocated=100.0, consumed=50.0)
        assert eng.identify_over_budget_consumers() == []

    def test_forecast_budget_exhaustion(self) -> None:
        eng = _budget_engine()
        eng.add_record(consumer_id="a1", allocated=100.0, consumed=10.0)
        eng.add_record(consumer_id="a1", allocated=100.0, consumed=20.0)
        result = eng.forecast_budget_exhaustion("a1")
        assert result["consumer_id"] == "a1"
        assert "total_allocated" in result
        assert "total_consumed" in result

    def test_forecast_budget_exhaustion_no_data(self) -> None:
        eng = _budget_engine()
        result = eng.forecast_budget_exhaustion("nonexistent")
        assert result["reason"] == "no_data"

    def test_recommend_budget_adjustments(self) -> None:
        eng = _budget_engine()
        eng.add_record(consumer_id="heavy", allocated=100.0, consumed=150.0)
        eng.add_record(consumer_id="light", allocated=100.0, consumed=10.0)
        results = eng.recommend_budget_adjustments()
        assert len(results) == 2
        heavy = [r for r in results if r["consumer_id"] == "heavy"][0]
        light = [r for r in results if r["consumer_id"] == "light"][0]
        assert heavy["action"] == "increase"
        assert light["action"] == "decrease"

    def test_recommend_budget_adjustments_maintain(self) -> None:
        eng = _budget_engine()
        eng.add_record(consumer_id="ok", allocated=100.0, consumed=60.0)
        results = eng.recommend_budget_adjustments()
        assert results[0]["action"] == "maintain"

    def test_generate_report_empty(self) -> None:
        eng = _budget_engine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert "healthy" in report.recommendations[0]


# ===========================================================================
# ConvergenceOptimizerEngine
# ===========================================================================


def _conv_engine(**kw: object) -> ConvergenceOptimizerEngine:
    return ConvergenceOptimizerEngine(**kw)


class TestConvergenceOptimizerEnums:
    def test_phase_warming_up(self) -> None:
        assert ConvergencePhase.WARMING_UP == "warming_up"

    def test_phase_improving(self) -> None:
        assert ConvergencePhase.IMPROVING == "improving"

    def test_phase_plateau(self) -> None:
        assert ConvergencePhase.PLATEAU == "plateau"

    def test_phase_diverging(self) -> None:
        assert ConvergencePhase.DIVERGING == "diverging"

    def test_action_continue(self) -> None:
        assert OptimizationAction.CONTINUE == "continue"

    def test_action_adjust_rate(self) -> None:
        assert OptimizationAction.ADJUST_RATE == "adjust_rate"

    def test_action_early_stop(self) -> None:
        assert OptimizationAction.EARLY_STOP == "early_stop"

    def test_action_restart(self) -> None:
        assert OptimizationAction.RESTART == "restart"

    def test_lr_constant(self) -> None:
        assert LearningRateStrategy.CONSTANT == "constant"

    def test_lr_decay(self) -> None:
        assert LearningRateStrategy.DECAY == "decay"

    def test_lr_adaptive(self) -> None:
        assert LearningRateStrategy.ADAPTIVE == "adaptive"

    def test_lr_cosine(self) -> None:
        assert LearningRateStrategy.COSINE == "cosine"


class TestConvergenceOptimizerModels:
    def test_record_defaults(self) -> None:
        r = ConvergenceOptimizerRecord()
        assert r.id
        assert r.loop_id == ""
        assert r.convergence_phase == ConvergencePhase.WARMING_UP
        assert r.optimization_action == OptimizationAction.CONTINUE
        assert r.learning_rate_strategy == LearningRateStrategy.CONSTANT
        assert r.metric_value == 0.0
        assert r.iteration == 0

    def test_analysis_defaults(self) -> None:
        a = ConvergenceOptimizerAnalysis()
        assert a.id
        assert a.loop_id == ""
        assert a.avg_delta == 0.0

    def test_report_defaults(self) -> None:
        rpt = ConvergenceOptimizerReport()
        assert rpt.id
        assert rpt.total_records == 0
        assert rpt.diverging_loops == []


class TestConvergenceOptimizerEngine:
    def test_add_record(self) -> None:
        eng = _conv_engine()
        rec = eng.add_record(
            loop_id="loop-1",
            convergence_phase=ConvergencePhase.IMPROVING,
            metric_value=0.85,
            metric_delta=0.05,
            iteration=10,
        )
        assert rec.loop_id == "loop-1"
        assert rec.metric_value == 0.85

    def test_ring_buffer_eviction(self) -> None:
        eng = _conv_engine(max_records=3)
        for i in range(5):
            eng.add_record(loop_id=f"loop-{i}")
        assert eng.get_stats()["total_records"] == 3

    def test_process_found(self) -> None:
        eng = _conv_engine()
        rec = eng.add_record(
            loop_id="loop-1",
            convergence_phase=ConvergencePhase.IMPROVING,
            metric_delta=0.05,
        )
        result = eng.process(rec.id)
        assert isinstance(result, ConvergenceOptimizerAnalysis)
        assert result.loop_id == "loop-1"

    def test_process_not_found(self) -> None:
        eng = _conv_engine()
        result = eng.process("nonexistent")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"

    def test_process_diverging_recommends_restart(self) -> None:
        eng = _conv_engine()
        rec = eng.add_record(
            loop_id="loop-d",
            convergence_phase=ConvergencePhase.DIVERGING,
            metric_delta=-0.1,
        )
        result = eng.process(rec.id)
        assert isinstance(result, ConvergenceOptimizerAnalysis)
        assert result.recommended_action == OptimizationAction.RESTART

    def test_generate_report_with_data(self) -> None:
        eng = _conv_engine()
        eng.add_record(
            loop_id="loop-1",
            convergence_phase=ConvergencePhase.IMPROVING,
            metric_value=0.8,
        )
        eng.add_record(
            loop_id="loop-2",
            convergence_phase=ConvergencePhase.DIVERGING,
            metric_value=0.3,
        )
        report = eng.generate_report()
        assert isinstance(report, ConvergenceOptimizerReport)
        assert report.total_records == 2
        assert "loop-2" in report.diverging_loops

    def test_get_stats(self) -> None:
        eng = _conv_engine()
        eng.add_record(loop_id="loop-1", convergence_phase=ConvergencePhase.PLATEAU)
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert "convergence_phase_distribution" in stats

    def test_clear_data(self) -> None:
        eng = _conv_engine()
        eng.add_record(loop_id="loop-1")
        result = eng.clear_data()
        assert result["status"] == "cleared"
        assert eng.get_stats()["total_records"] == 0

    def test_detect_plateau_true(self) -> None:
        eng = _conv_engine()
        for i in range(6):
            eng.add_record(
                loop_id="loop-p",
                metric_delta=0.0001,
                iteration=i,
            )
        result = eng.detect_plateau("loop-p", window=5)
        assert result["plateaued"] is True

    def test_detect_plateau_false(self) -> None:
        eng = _conv_engine()
        for i in range(6):
            eng.add_record(
                loop_id="loop-np",
                metric_delta=0.1,
                iteration=i,
            )
        result = eng.detect_plateau("loop-np", window=5)
        assert result["plateaued"] is False

    def test_detect_plateau_insufficient_data(self) -> None:
        eng = _conv_engine()
        eng.add_record(loop_id="loop-s", metric_delta=0.01, iteration=0)
        result = eng.detect_plateau("loop-s", window=5)
        assert result["plateaued"] is False
        assert result["reason"] == "insufficient_data"

    def test_recommend_learning_rate_diverging(self) -> None:
        eng = _conv_engine()
        eng.add_record(
            loop_id="loop-div",
            convergence_phase=ConvergencePhase.DIVERGING,
            metric_delta=-0.1,
            iteration=1,
        )
        result = eng.recommend_learning_rate("loop-div")
        assert result["recommended_strategy"] == "decay"
        assert result["rate_multiplier"] == 0.5

    def test_recommend_learning_rate_plateau(self) -> None:
        eng = _conv_engine()
        eng.add_record(
            loop_id="loop-pl",
            convergence_phase=ConvergencePhase.PLATEAU,
            metric_delta=-0.001,
            iteration=1,
        )
        result = eng.recommend_learning_rate("loop-pl")
        assert result["recommended_strategy"] == "adaptive"

    def test_recommend_learning_rate_no_data(self) -> None:
        eng = _conv_engine()
        result = eng.recommend_learning_rate("nonexistent")
        assert result["reason"] == "no_data"

    def test_estimate_remaining_iterations(self) -> None:
        eng = _conv_engine()
        for i in range(5):
            eng.add_record(
                loop_id="loop-est",
                metric_value=0.5 + i * 0.1,
                metric_delta=0.1,
                iteration=i,
            )
        result = eng.estimate_remaining_iterations("loop-est", target_metric=1.5)
        assert result["estimated_iterations"] > 0
        assert result["current_value"] == 0.9

    def test_estimate_remaining_target_reached(self) -> None:
        eng = _conv_engine()
        eng.add_record(loop_id="loop-done", metric_value=1.0, metric_delta=0.1, iteration=1)
        eng.add_record(loop_id="loop-done", metric_value=1.5, metric_delta=0.1, iteration=2)
        result = eng.estimate_remaining_iterations("loop-done", target_metric=1.0)
        assert result["estimated_iterations"] == 0
        assert result["reason"] == "target_already_reached"

    def test_estimate_remaining_insufficient_data(self) -> None:
        eng = _conv_engine()
        eng.add_record(loop_id="loop-one", metric_value=0.5, iteration=1)
        result = eng.estimate_remaining_iterations("loop-one", target_metric=1.0)
        assert result["estimated_iterations"] == -1

    def test_generate_report_empty(self) -> None:
        eng = _conv_engine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert "healthy" in report.recommendations[0]
