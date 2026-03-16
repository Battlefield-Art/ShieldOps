"""Tests for agent optimization engines — benchmark, tuner, coordination, efficiency."""

from __future__ import annotations

from shieldops.analytics.agent_performance_benchmark_engine import (
    AgentPerformanceBenchmarkEngine,
    BenchmarkAnalysis,
    BenchmarkBaseline,
    BenchmarkDimension,
    BenchmarkRecord,
    BenchmarkReport,
    PerformanceTrend,
)
from shieldops.analytics.agent_resource_efficiency_engine import (
    AgentResourceEfficiencyEngine,
    EfficiencyAnalysis,
    EfficiencyGrade,
    EfficiencyRecord,
    EfficiencyReport,
    OptimizationTarget,
    ResourceMetric,
)
from shieldops.analytics.hyperparameter_auto_tuner_engine import (
    HyperparameterAutoTunerEngine,
    ParameterType,
    TuningAnalysis,
    TuningOutcome,
    TuningRecord,
    TuningReport,
    TuningStrategy,
)
from shieldops.analytics.multi_agent_coordination_engine import (
    ConflictType,
    CoordinationAnalysis,
    CoordinationMode,
    CoordinationRecord,
    CoordinationReport,
    MultiAgentCoordinationEngine,
    ResolutionStrategy,
)

# ===========================================================================
# AgentPerformanceBenchmarkEngine
# ===========================================================================


class TestBenchmarkEnums:
    def test_dimension_accuracy(self):
        assert BenchmarkDimension.ACCURACY == "accuracy"

    def test_dimension_latency(self):
        assert BenchmarkDimension.LATENCY == "latency"

    def test_dimension_cost_efficiency(self):
        assert BenchmarkDimension.COST_EFFICIENCY == "cost_efficiency"

    def test_dimension_reliability(self):
        assert BenchmarkDimension.RELIABILITY == "reliability"

    def test_baseline_industry(self):
        assert BenchmarkBaseline.INDUSTRY_STANDARD == "industry_standard"

    def test_baseline_historical(self):
        assert BenchmarkBaseline.HISTORICAL_BEST == "historical_best"

    def test_baseline_peer(self):
        assert BenchmarkBaseline.PEER_COMPARISON == "peer_comparison"

    def test_baseline_sla(self):
        assert BenchmarkBaseline.TARGET_SLA == "target_sla"

    def test_trend_improving(self):
        assert PerformanceTrend.IMPROVING == "improving"

    def test_trend_stable(self):
        assert PerformanceTrend.STABLE == "stable"

    def test_trend_degrading(self):
        assert PerformanceTrend.DEGRADING == "degrading"

    def test_trend_volatile(self):
        assert PerformanceTrend.VOLATILE == "volatile"


class TestBenchmarkModels:
    def test_record_defaults(self):
        r = BenchmarkRecord()
        assert r.id
        assert r.agent_id == ""
        assert r.dimension == BenchmarkDimension.ACCURACY
        assert r.baseline == BenchmarkBaseline.INDUSTRY_STANDARD
        assert r.trend == PerformanceTrend.STABLE
        assert r.score == 0.0
        assert r.created_at > 0

    def test_analysis_defaults(self):
        a = BenchmarkAnalysis()
        assert a.id
        assert a.agent_id == ""
        assert a.analysis_score == 0.0
        assert a.breached is False

    def test_report_defaults(self):
        r = BenchmarkReport()
        assert r.total_records == 0
        assert r.by_dimension == {}
        assert r.recommendations == []
        assert r.generated_at > 0


class TestBenchmarkAddRecord:
    def test_basic(self):
        eng = AgentPerformanceBenchmarkEngine()
        r = eng.add_record(
            agent_id="agent-1",
            dimension=BenchmarkDimension.LATENCY,
            score=85.0,
            service="api-gw",
            team="platform",
        )
        assert r.agent_id == "agent-1"
        assert r.dimension == BenchmarkDimension.LATENCY
        assert r.score == 85.0

    def test_eviction(self):
        eng = AgentPerformanceBenchmarkEngine(max_records=3)
        for i in range(5):
            eng.add_record(agent_id=f"agent-{i}")
        assert len(eng._records) == 3


class TestBenchmarkGetRecord:
    def test_found(self):
        eng = AgentPerformanceBenchmarkEngine()
        r = eng.add_record(agent_id="agent-1")
        assert eng.get_record(r.id) is not None

    def test_not_found(self):
        eng = AgentPerformanceBenchmarkEngine()
        assert eng.get_record("missing") is None


class TestBenchmarkListRecords:
    def test_filter_dimension(self):
        eng = AgentPerformanceBenchmarkEngine()
        eng.add_record(agent_id="a1", dimension=BenchmarkDimension.ACCURACY)
        eng.add_record(agent_id="a2", dimension=BenchmarkDimension.LATENCY)
        assert len(eng.list_records(dimension=BenchmarkDimension.ACCURACY)) == 1

    def test_filter_team(self):
        eng = AgentPerformanceBenchmarkEngine()
        eng.add_record(agent_id="a1", team="sre")
        eng.add_record(agent_id="a2", team="security")
        assert len(eng.list_records(team="sre")) == 1

    def test_limit(self):
        eng = AgentPerformanceBenchmarkEngine()
        for i in range(10):
            eng.add_record(agent_id=f"a-{i}")
        assert len(eng.list_records(limit=5)) == 5


class TestBenchmarkAnalysis:
    def test_add_analysis(self):
        eng = AgentPerformanceBenchmarkEngine()
        a = eng.add_analysis(
            agent_id="agent-1",
            dimension=BenchmarkDimension.COST_EFFICIENCY,
            analysis_score=72.0,
            breached=True,
        )
        assert a.agent_id == "agent-1"
        assert a.breached is True

    def test_eviction(self):
        eng = AgentPerformanceBenchmarkEngine(max_records=2)
        for i in range(5):
            eng.add_analysis(agent_id=f"a-{i}")
        assert len(eng._analyses) == 2


class TestBenchmarkDomainMethods:
    def test_compute_benchmark_score(self):
        eng = AgentPerformanceBenchmarkEngine()
        eng.add_record(agent_id="a1", dimension=BenchmarkDimension.ACCURACY, score=80.0)
        eng.add_record(agent_id="a1", dimension=BenchmarkDimension.LATENCY, score=60.0)
        result = eng.compute_benchmark_score("a1")
        assert result["agent_id"] == "a1"
        assert result["overall_score"] == 70.0
        assert "accuracy" in result["dimensions"]

    def test_compute_benchmark_score_empty(self):
        eng = AgentPerformanceBenchmarkEngine()
        result = eng.compute_benchmark_score("missing")
        assert result["overall_score"] == 0.0

    def test_compare_against_baseline_above(self):
        eng = AgentPerformanceBenchmarkEngine(score_threshold=70.0)
        eng.add_record(
            agent_id="a1",
            baseline=BenchmarkBaseline.INDUSTRY_STANDARD,
            score=90.0,
        )
        result = eng.compare_against_baseline("a1", BenchmarkBaseline.INDUSTRY_STANDARD)
        assert result["comparison"] == "above_baseline"
        assert result["delta"] == 20.0

    def test_compare_against_baseline_no_data(self):
        eng = AgentPerformanceBenchmarkEngine()
        result = eng.compare_against_baseline("missing", BenchmarkBaseline.PEER_COMPARISON)
        assert result["comparison"] == "no_data"

    def test_identify_regressions(self):
        eng = AgentPerformanceBenchmarkEngine()
        eng.add_record(agent_id="a1", score=90.0)
        eng.add_record(agent_id="a1", score=88.0)
        eng.add_record(agent_id="a1", score=40.0)
        eng.add_record(agent_id="a1", score=38.0)
        result = eng.identify_performance_regressions()
        assert len(result) == 1
        assert result[0]["agent_id"] == "a1"
        assert result[0]["delta"] < 0

    def test_identify_regressions_empty(self):
        eng = AgentPerformanceBenchmarkEngine()
        assert eng.identify_performance_regressions() == []


class TestBenchmarkReportAndStats:
    def test_report_populated(self):
        eng = AgentPerformanceBenchmarkEngine(score_threshold=80.0)
        eng.add_record(agent_id="a1", score=60.0)
        report = eng.generate_report()
        assert isinstance(report, BenchmarkReport)
        assert report.total_records == 1
        assert report.low_score_count == 1
        assert len(report.recommendations) > 0

    def test_report_empty(self):
        eng = AgentPerformanceBenchmarkEngine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self):
        eng = AgentPerformanceBenchmarkEngine()
        eng.add_record(agent_id="a1")
        eng.add_analysis(agent_id="a1")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0

    def test_get_stats_empty(self):
        eng = AgentPerformanceBenchmarkEngine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0
        assert stats["dimension_distribution"] == {}

    def test_get_stats_populated(self):
        eng = AgentPerformanceBenchmarkEngine()
        eng.add_record(agent_id="a1", team="sre", service="api")
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_agents"] == 1
        assert stats["unique_teams"] == 1


# ===========================================================================
# HyperparameterAutoTunerEngine
# ===========================================================================


class TestTunerEnums:
    def test_strategy_grid(self):
        assert TuningStrategy.GRID_SEARCH == "grid_search"

    def test_strategy_random(self):
        assert TuningStrategy.RANDOM_SEARCH == "random_search"

    def test_strategy_bayesian(self):
        assert TuningStrategy.BAYESIAN == "bayesian"

    def test_strategy_evolutionary(self):
        assert TuningStrategy.EVOLUTIONARY == "evolutionary"

    def test_param_threshold(self):
        assert ParameterType.THRESHOLD == "threshold"

    def test_param_timeout(self):
        assert ParameterType.TIMEOUT == "timeout"

    def test_param_batch_size(self):
        assert ParameterType.BATCH_SIZE == "batch_size"

    def test_param_learning_rate(self):
        assert ParameterType.LEARNING_RATE == "learning_rate"

    def test_outcome_improved(self):
        assert TuningOutcome.IMPROVED == "improved"

    def test_outcome_no_change(self):
        assert TuningOutcome.NO_CHANGE == "no_change"

    def test_outcome_degraded(self):
        assert TuningOutcome.DEGRADED == "degraded"

    def test_outcome_invalid(self):
        assert TuningOutcome.INVALID == "invalid"


class TestTunerModels:
    def test_record_defaults(self):
        r = TuningRecord()
        assert r.id
        assert r.agent_id == ""
        assert r.strategy == TuningStrategy.BAYESIAN
        assert r.parameter_type == ParameterType.THRESHOLD
        assert r.outcome == TuningOutcome.NO_CHANGE
        assert r.score == 0.0

    def test_analysis_defaults(self):
        a = TuningAnalysis()
        assert a.id
        assert a.analysis_score == 0.0
        assert a.breached is False

    def test_report_defaults(self):
        r = TuningReport()
        assert r.total_records == 0
        assert r.by_strategy == {}
        assert r.recommendations == []


class TestTunerAddRecord:
    def test_basic(self):
        eng = HyperparameterAutoTunerEngine()
        r = eng.add_record(
            agent_id="a1",
            strategy=TuningStrategy.GRID_SEARCH,
            parameter_type=ParameterType.TIMEOUT,
            outcome=TuningOutcome.IMPROVED,
            score=85.0,
        )
        assert r.agent_id == "a1"
        assert r.strategy == TuningStrategy.GRID_SEARCH
        assert r.outcome == TuningOutcome.IMPROVED

    def test_eviction(self):
        eng = HyperparameterAutoTunerEngine(max_records=3)
        for i in range(5):
            eng.add_record(agent_id=f"a-{i}")
        assert len(eng._records) == 3


class TestTunerDomainMethods:
    def test_propose_no_history(self):
        eng = HyperparameterAutoTunerEngine()
        result = eng.propose_parameter_change("a1")
        assert result["agent_id"] == "a1"
        assert result["reason"] == "no_history_default_proposal"

    def test_propose_with_history(self):
        eng = HyperparameterAutoTunerEngine()
        eng.add_record(
            agent_id="a1",
            parameter_type=ParameterType.THRESHOLD,
            score=90.0,
            outcome=TuningOutcome.IMPROVED,
            strategy=TuningStrategy.BAYESIAN,
        )
        eng.add_record(
            agent_id="a1",
            parameter_type=ParameterType.TIMEOUT,
            score=30.0,
            outcome=TuningOutcome.NO_CHANGE,
        )
        result = eng.propose_parameter_change("a1")
        assert result["proposed_parameter"] == "timeout"

    def test_evaluate_not_found(self):
        eng = HyperparameterAutoTunerEngine()
        result = eng.evaluate_tuning_result("missing")
        assert result["decision"] == "not_found"

    def test_evaluate_accept(self):
        eng = HyperparameterAutoTunerEngine(improvement_threshold=5.0)
        eng.add_record(agent_id="a1", score=50.0)
        r = eng.add_record(agent_id="a1", score=80.0)
        result = eng.evaluate_tuning_result(r.id)
        assert result["decision"] == "accept"
        assert result["delta"] > 0

    def test_evaluate_reject(self):
        eng = HyperparameterAutoTunerEngine(improvement_threshold=5.0)
        eng.add_record(agent_id="a1", score=80.0)
        r = eng.add_record(agent_id="a1", score=30.0)
        result = eng.evaluate_tuning_result(r.id)
        assert result["decision"] == "reject"

    def test_compute_optimal_empty(self):
        eng = HyperparameterAutoTunerEngine()
        result = eng.compute_optimal_parameters("missing")
        assert result["optimal_parameters"] == {}

    def test_compute_optimal_with_data(self):
        eng = HyperparameterAutoTunerEngine()
        eng.add_record(
            agent_id="a1",
            parameter_type=ParameterType.THRESHOLD,
            score=60.0,
        )
        eng.add_record(
            agent_id="a1",
            parameter_type=ParameterType.THRESHOLD,
            score=90.0,
        )
        result = eng.compute_optimal_parameters("a1")
        assert result["optimal_parameters"]["threshold"]["best_score"] == 90.0


class TestTunerReportAndStats:
    def test_report_populated(self):
        eng = HyperparameterAutoTunerEngine()
        eng.add_record(agent_id="a1", outcome=TuningOutcome.DEGRADED, score=10.0)
        report = eng.generate_report()
        assert isinstance(report, TuningReport)
        assert report.degraded_count == 1
        assert len(report.recommendations) > 0

    def test_report_empty(self):
        eng = HyperparameterAutoTunerEngine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self):
        eng = HyperparameterAutoTunerEngine()
        eng.add_record(agent_id="a1")
        eng.add_analysis(agent_id="a1")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0

    def test_get_stats(self):
        eng = HyperparameterAutoTunerEngine()
        eng.add_record(agent_id="a1", team="sre")
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_agents"] == 1


# ===========================================================================
# MultiAgentCoordinationEngine
# ===========================================================================


class TestCoordinationEnums:
    def test_mode_sequential(self):
        assert CoordinationMode.SEQUENTIAL == "sequential"

    def test_mode_parallel(self):
        assert CoordinationMode.PARALLEL == "parallel"

    def test_mode_pipeline(self):
        assert CoordinationMode.PIPELINE == "pipeline"

    def test_mode_hierarchical(self):
        assert CoordinationMode.HIERARCHICAL == "hierarchical"

    def test_conflict_resource(self):
        assert ConflictType.RESOURCE_CONTENTION == "resource_contention"

    def test_conflict_action(self):
        assert ConflictType.ACTION_CONFLICT == "action_conflict"

    def test_conflict_state(self):
        assert ConflictType.STATE_INCONSISTENCY == "state_inconsistency"

    def test_conflict_priority(self):
        assert ConflictType.PRIORITY_CLASH == "priority_clash"

    def test_resolution_priority(self):
        assert ResolutionStrategy.PRIORITY_BASED == "priority_based"

    def test_resolution_consensus(self):
        assert ResolutionStrategy.CONSENSUS == "consensus"

    def test_resolution_timeout(self):
        assert ResolutionStrategy.TIMEOUT == "timeout"

    def test_resolution_escalation(self):
        assert ResolutionStrategy.ESCALATION == "escalation"


class TestCoordinationModels:
    def test_record_defaults(self):
        r = CoordinationRecord()
        assert r.id
        assert r.task_id == ""
        assert r.coordination_mode == CoordinationMode.SEQUENTIAL
        assert r.overhead_ms == 0.0

    def test_analysis_defaults(self):
        a = CoordinationAnalysis()
        assert a.id
        assert a.analysis_score == 0.0

    def test_report_defaults(self):
        r = CoordinationReport()
        assert r.total_records == 0
        assert r.by_mode == {}


class TestCoordinationAddRecord:
    def test_basic(self):
        eng = MultiAgentCoordinationEngine()
        r = eng.add_record(
            task_id="task-1",
            coordination_mode=CoordinationMode.PARALLEL,
            conflict_type=ConflictType.ACTION_CONFLICT,
            overhead_ms=250.0,
        )
        assert r.task_id == "task-1"
        assert r.coordination_mode == CoordinationMode.PARALLEL
        assert r.overhead_ms == 250.0

    def test_eviction(self):
        eng = MultiAgentCoordinationEngine(max_records=3)
        for i in range(5):
            eng.add_record(task_id=f"t-{i}")
        assert len(eng._records) == 3


class TestCoordinationDomainMethods:
    def test_detect_conflicts(self):
        eng = MultiAgentCoordinationEngine(overhead_threshold=200.0)
        eng.add_record(task_id="t1", overhead_ms=100.0)
        eng.add_record(task_id="t2", overhead_ms=500.0)
        eng.add_record(task_id="t3", overhead_ms=800.0)
        result = eng.detect_coordination_conflicts()
        assert len(result) == 2
        assert result[0]["overhead_ms"] == 800.0

    def test_detect_conflicts_empty(self):
        eng = MultiAgentCoordinationEngine()
        assert eng.detect_coordination_conflicts() == []

    def test_recommend_mode_no_history(self):
        eng = MultiAgentCoordinationEngine()
        result = eng.recommend_coordination_mode("incident")
        assert result["recommended_mode"] == "sequential"
        assert result["reason"] == "no_history_default"

    def test_recommend_mode_with_history(self):
        eng = MultiAgentCoordinationEngine()
        eng.add_record(
            task_id="incident",
            coordination_mode=CoordinationMode.PARALLEL,
            overhead_ms=100.0,
        )
        eng.add_record(
            task_id="incident",
            coordination_mode=CoordinationMode.SEQUENTIAL,
            overhead_ms=500.0,
        )
        result = eng.recommend_coordination_mode("incident")
        assert result["recommended_mode"] == "parallel"

    def test_measure_overhead_empty(self):
        eng = MultiAgentCoordinationEngine()
        result = eng.measure_coordination_overhead()
        assert result["total_overhead_ms"] == 0.0

    def test_measure_overhead_with_data(self):
        eng = MultiAgentCoordinationEngine()
        eng.add_record(
            task_id="t1",
            coordination_mode=CoordinationMode.PARALLEL,
            overhead_ms=100.0,
        )
        eng.add_record(
            task_id="t2",
            coordination_mode=CoordinationMode.PARALLEL,
            overhead_ms=200.0,
        )
        result = eng.measure_coordination_overhead()
        assert result["total_overhead_ms"] == 300.0
        assert result["by_mode"]["parallel"]["count"] == 2


class TestCoordinationReportAndStats:
    def test_report_populated(self):
        eng = MultiAgentCoordinationEngine(overhead_threshold=100.0)
        eng.add_record(task_id="t1", overhead_ms=500.0)
        report = eng.generate_report()
        assert isinstance(report, CoordinationReport)
        assert report.high_overhead_count == 1
        assert len(report.recommendations) > 0

    def test_report_empty(self):
        eng = MultiAgentCoordinationEngine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self):
        eng = MultiAgentCoordinationEngine()
        eng.add_record(task_id="t1")
        eng.add_analysis(task_id="t1")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0

    def test_get_stats(self):
        eng = MultiAgentCoordinationEngine()
        eng.add_record(task_id="t1", team="sre", service="api")
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_tasks"] == 1


# ===========================================================================
# AgentResourceEfficiencyEngine
# ===========================================================================


class TestEfficiencyEnums:
    def test_metric_tokens(self):
        assert ResourceMetric.TOKEN_USAGE == "token_usage"

    def test_metric_api_calls(self):
        assert ResourceMetric.API_CALLS == "api_calls"

    def test_metric_compute(self):
        assert ResourceMetric.COMPUTE_SECONDS == "compute_seconds"

    def test_metric_memory(self):
        assert ResourceMetric.MEMORY_PEAK == "memory_peak"

    def test_grade_excellent(self):
        assert EfficiencyGrade.EXCELLENT == "excellent"

    def test_grade_good(self):
        assert EfficiencyGrade.GOOD == "good"

    def test_grade_fair(self):
        assert EfficiencyGrade.FAIR == "fair"

    def test_grade_poor(self):
        assert EfficiencyGrade.POOR == "poor"

    def test_target_tokens(self):
        assert OptimizationTarget.REDUCE_TOKENS == "reduce_tokens"

    def test_target_latency(self):
        assert OptimizationTarget.REDUCE_LATENCY == "reduce_latency"

    def test_target_cost(self):
        assert OptimizationTarget.REDUCE_COST == "reduce_cost"

    def test_target_accuracy(self):
        assert OptimizationTarget.IMPROVE_ACCURACY == "improve_accuracy"


class TestEfficiencyModels:
    def test_record_defaults(self):
        r = EfficiencyRecord()
        assert r.id
        assert r.agent_id == ""
        assert r.resource_metric == ResourceMetric.TOKEN_USAGE
        assert r.grade == EfficiencyGrade.GOOD
        assert r.usage_value == 0.0

    def test_analysis_defaults(self):
        a = EfficiencyAnalysis()
        assert a.id
        assert a.analysis_score == 0.0

    def test_report_defaults(self):
        r = EfficiencyReport()
        assert r.total_records == 0
        assert r.by_metric == {}


class TestEfficiencyAddRecord:
    def test_basic(self):
        eng = AgentResourceEfficiencyEngine()
        r = eng.add_record(
            agent_id="a1",
            resource_metric=ResourceMetric.API_CALLS,
            grade=EfficiencyGrade.POOR,
            usage_value=150.0,
        )
        assert r.agent_id == "a1"
        assert r.resource_metric == ResourceMetric.API_CALLS
        assert r.grade == EfficiencyGrade.POOR

    def test_eviction(self):
        eng = AgentResourceEfficiencyEngine(max_records=3)
        for i in range(5):
            eng.add_record(agent_id=f"a-{i}")
        assert len(eng._records) == 3


class TestEfficiencyDomainMethods:
    def test_compute_efficiency_score(self):
        eng = AgentResourceEfficiencyEngine()
        eng.add_record(
            agent_id="a1",
            resource_metric=ResourceMetric.TOKEN_USAGE,
            usage_value=100.0,
        )
        eng.add_record(
            agent_id="a1",
            resource_metric=ResourceMetric.API_CALLS,
            usage_value=50.0,
        )
        result = eng.compute_efficiency_score("a1")
        assert result["agent_id"] == "a1"
        assert result["overall_efficiency"] == 75.0
        assert "token_usage" in result["by_metric"]

    def test_compute_efficiency_empty(self):
        eng = AgentResourceEfficiencyEngine()
        result = eng.compute_efficiency_score("missing")
        assert result["overall_efficiency"] == 0.0

    def test_identify_resource_waste(self):
        eng = AgentResourceEfficiencyEngine()
        eng.add_record(agent_id="a1", grade=EfficiencyGrade.POOR, usage_value=200.0)
        eng.add_record(agent_id="a2", grade=EfficiencyGrade.EXCELLENT, usage_value=10.0)
        result = eng.identify_resource_waste()
        assert len(result) == 1
        assert result[0]["agent_id"] == "a1"
        assert result[0]["waste_ratio"] == 1.0

    def test_identify_waste_empty(self):
        eng = AgentResourceEfficiencyEngine()
        assert eng.identify_resource_waste() == []

    def test_recommend_optimizations(self):
        eng = AgentResourceEfficiencyEngine(efficiency_threshold=50.0)
        eng.add_record(
            agent_id="a1",
            resource_metric=ResourceMetric.TOKEN_USAGE,
            usage_value=200.0,
        )
        result = eng.recommend_optimizations()
        assert len(result) == 1
        assert result[0]["agent_id"] == "a1"
        assert result[0]["recommended_target"] == "reduce_tokens"

    def test_recommend_optimizations_empty(self):
        eng = AgentResourceEfficiencyEngine()
        assert eng.recommend_optimizations() == []


class TestEfficiencyReportAndStats:
    def test_report_populated(self):
        eng = AgentResourceEfficiencyEngine()
        eng.add_record(agent_id="a1", grade=EfficiencyGrade.POOR, usage_value=100.0)
        report = eng.generate_report()
        assert isinstance(report, EfficiencyReport)
        assert report.poor_efficiency_count == 1
        assert len(report.recommendations) > 0

    def test_report_empty(self):
        eng = AgentResourceEfficiencyEngine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self):
        eng = AgentResourceEfficiencyEngine()
        eng.add_record(agent_id="a1")
        eng.add_analysis(agent_id="a1")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0

    def test_get_stats_empty(self):
        eng = AgentResourceEfficiencyEngine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0
        assert stats["metric_distribution"] == {}

    def test_get_stats_populated(self):
        eng = AgentResourceEfficiencyEngine()
        eng.add_record(agent_id="a1", team="sre", service="api")
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_agents"] == 1
        assert stats["unique_teams"] == 1
