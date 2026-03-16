"""Tests for Phase 135 Engines — AdaptiveThresholdEngine, RiskTimelineEngine,
AgentCurriculumEngine, ExperimentReplayEngine, ResourceEfficiencyOptimizerEngine."""

from __future__ import annotations

from shieldops.analytics.agent_curriculum_engine import (
    AgentCurriculumAnalysis,
    AgentCurriculumEngine,
    AgentCurriculumRecord,
    AgentCurriculumReport,
    CurriculumStatus,
    DifficultyLevel,
    LearningObjective,
)
from shieldops.analytics.experiment_replay_engine import (
    ExperimentReplayAnalysis,
    ExperimentReplayEngine,
    ExperimentReplayRecord,
    ExperimentReplayReport,
    InsightType,
    ReplayOutcome,
    ReplayStrategy,
)
from shieldops.analytics.resource_efficiency_optimizer_engine import (
    EfficiencyTrend,
    OptimizationGoal,
    ResourceEfficiencyOptimizerAnalysis,
    ResourceEfficiencyOptimizerEngine,
    ResourceEfficiencyOptimizerRecord,
    ResourceEfficiencyOptimizerReport,
    ResourceType,
)
from shieldops.security.adaptive_threshold_engine import (
    AdaptationStrategy,
    AdaptiveThresholdAnalysis,
    AdaptiveThresholdEngine,
    AdaptiveThresholdRecord,
    AdaptiveThresholdReport,
    DriftDirection,
    ThresholdStatus,
)
from shieldops.security.risk_timeline_engine import (
    RiskPhase,
    RiskTimelineAnalysis,
    RiskTimelineEngine,
    RiskTimelineRecord,
    RiskTimelineReport,
    TimelineGranularity,
    TrendDirection,
)

# ============================================================================
# AdaptiveThresholdEngine
# ============================================================================


class TestAdaptiveThresholdEnums:
    def test_drift_increasing(self) -> None:
        assert DriftDirection.INCREASING == "increasing"

    def test_drift_decreasing(self) -> None:
        assert DriftDirection.DECREASING == "decreasing"

    def test_drift_stable(self) -> None:
        assert DriftDirection.STABLE == "stable"

    def test_strategy_conservative(self) -> None:
        assert AdaptationStrategy.CONSERVATIVE == "conservative"

    def test_strategy_moderate(self) -> None:
        assert AdaptationStrategy.MODERATE == "moderate"

    def test_strategy_aggressive(self) -> None:
        assert AdaptationStrategy.AGGRESSIVE == "aggressive"

    def test_status_active(self) -> None:
        assert ThresholdStatus.ACTIVE == "active"

    def test_status_proposed(self) -> None:
        assert ThresholdStatus.PROPOSED == "proposed"

    def test_status_retired(self) -> None:
        assert ThresholdStatus.RETIRED == "retired"


class TestAdaptiveThresholdModels:
    def test_record_defaults(self) -> None:
        r = AdaptiveThresholdRecord()
        assert r.id
        assert r.drift_direction == DriftDirection.STABLE
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = AdaptiveThresholdAnalysis()
        assert a.id
        assert a.breached is False

    def test_report_defaults(self) -> None:
        r = AdaptiveThresholdReport()
        assert r.total_records == 0


class TestAdaptiveThresholdEngine:
    def _engine(self, **kw: object) -> AdaptiveThresholdEngine:
        return AdaptiveThresholdEngine(**kw)

    def test_init(self) -> None:
        e = self._engine()
        assert e._threshold == 50.0

    def test_add_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="thresh-1", score=70.0, entity="user-1")
        assert r.name == "thresh-1"
        assert r.entity == "user-1"

    def test_get_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="t1")
        assert e.get_record(r.id) is not None

    def test_get_record_not_found(self) -> None:
        e = self._engine()
        assert e.get_record("nope") is None

    def test_list_records_filter_drift(self) -> None:
        e = self._engine()
        e.add_record(name="r1", drift_direction=DriftDirection.INCREASING)
        e.add_record(name="r2", drift_direction=DriftDirection.STABLE)
        results = e.list_records(drift_direction=DriftDirection.INCREASING)
        assert len(results) == 1

    def test_add_analysis(self) -> None:
        e = self._engine()
        a = e.add_analysis(name="analysis-1", analysis_score=65.0)
        assert a.analysis_score == 65.0

    def test_compute_optimal_thresholds(self) -> None:
        e = self._engine()
        e.add_record(
            name="t1",
            entity="user-1",
            baseline_value=100.0,
            current_threshold=80.0,
            adaptation_strategy=AdaptationStrategy.MODERATE,
        )
        results = e.compute_optimal_thresholds()
        assert len(results) == 1
        assert results[0]["entity"] == "user-1"
        assert results[0]["optimal_threshold"] == 120.0

    def test_detect_threshold_staleness(self) -> None:
        e = self._engine()
        e.add_record(
            name="t1",
            entity="user-1",
            baseline_value=50.0,
            current_threshold=80.0,
        )
        e.add_record(
            name="t2",
            entity="user-1",
            baseline_value=100.0,
            current_threshold=81.0,
        )
        stale = e.detect_threshold_staleness()
        assert len(stale) == 1
        assert stale[0]["staleness"] == "high"

    def test_detect_threshold_staleness_not_stale(self) -> None:
        e = self._engine()
        e.add_record(name="t1", entity="user-1", baseline_value=50.0, current_threshold=50.0)
        e.add_record(name="t2", entity="user-1", baseline_value=55.0, current_threshold=55.0)
        stale = e.detect_threshold_staleness()
        assert len(stale) == 0

    def test_evaluate_adaptation_impact(self) -> None:
        e = self._engine()
        e.add_record(
            name="r1",
            adaptation_strategy=AdaptationStrategy.CONSERVATIVE,
            score=80.0,
        )
        e.add_record(
            name="r2",
            adaptation_strategy=AdaptationStrategy.AGGRESSIVE,
            score=40.0,
        )
        impact = e.evaluate_adaptation_impact()
        assert "conservative" in impact
        assert "aggressive" in impact

    def test_generate_report(self) -> None:
        e = self._engine()
        e.add_record(name="r1", score=80.0)
        report = e.generate_report()
        assert report.total_records == 1

    def test_clear_data(self) -> None:
        e = self._engine()
        e.add_record(name="r1")
        e.clear_data()
        assert e.get_stats()["total_records"] == 0

    def test_get_stats(self) -> None:
        e = self._engine()
        e.add_record(name="r1", team="t1")
        stats = e.get_stats()
        assert stats["unique_teams"] == 1

    def test_process(self) -> None:
        e = self._engine()
        e.add_record(name="test", score=60.0)
        result = e.process("test")
        assert result["status"] == "processed"

    def test_ring_buffer(self) -> None:
        e = self._engine(max_records=3)
        for i in range(5):
            e.add_record(name=f"r{i}")
        assert len(e._records) == 3


# ============================================================================
# RiskTimelineEngine
# ============================================================================


class TestRiskTimelineEnums:
    def test_granularity_minute(self) -> None:
        assert TimelineGranularity.MINUTE == "minute"

    def test_granularity_hour(self) -> None:
        assert TimelineGranularity.HOUR == "hour"

    def test_granularity_day(self) -> None:
        assert TimelineGranularity.DAY == "day"

    def test_granularity_week(self) -> None:
        assert TimelineGranularity.WEEK == "week"

    def test_trend_rising(self) -> None:
        assert TrendDirection.RISING == "rising"

    def test_trend_falling(self) -> None:
        assert TrendDirection.FALLING == "falling"

    def test_trend_stable(self) -> None:
        assert TrendDirection.STABLE == "stable"

    def test_trend_volatile(self) -> None:
        assert TrendDirection.VOLATILE == "volatile"

    def test_phase_baseline(self) -> None:
        assert RiskPhase.BASELINE == "baseline"

    def test_phase_escalation(self) -> None:
        assert RiskPhase.ESCALATION == "escalation"

    def test_phase_peak(self) -> None:
        assert RiskPhase.PEAK == "peak"

    def test_phase_recovery(self) -> None:
        assert RiskPhase.RECOVERY == "recovery"


class TestRiskTimelineModels:
    def test_record_defaults(self) -> None:
        r = RiskTimelineRecord()
        assert r.id
        assert r.trend_direction == TrendDirection.STABLE
        assert r.risk_phase == RiskPhase.BASELINE

    def test_analysis_defaults(self) -> None:
        a = RiskTimelineAnalysis()
        assert a.breached is False

    def test_report_defaults(self) -> None:
        r = RiskTimelineReport()
        assert r.total_records == 0


class TestRiskTimelineEngine:
    def _engine(self, **kw: object) -> RiskTimelineEngine:
        return RiskTimelineEngine(**kw)

    def test_add_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="timeline-1", entity="host-1", risk_score=75.0)
        assert r.entity == "host-1"

    def test_get_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="t1")
        assert e.get_record(r.id) is not None

    def test_list_records_filter(self) -> None:
        e = self._engine()
        e.add_record(name="r1", trend_direction=TrendDirection.RISING)
        e.add_record(name="r2", trend_direction=TrendDirection.STABLE)
        results = e.list_records(trend_direction=TrendDirection.RISING)
        assert len(results) == 1

    def test_compute_risk_trajectory(self) -> None:
        e = self._engine()
        e.add_record(name="t1", entity="host-1", risk_score=20.0)
        e.add_record(name="t2", entity="host-1", risk_score=80.0)
        trajectories = e.compute_risk_trajectory()
        assert len(trajectories) == 1
        assert trajectories[0]["trajectory"] == "escalating"

    def test_compute_risk_trajectory_insufficient(self) -> None:
        e = self._engine()
        e.add_record(name="t1", entity="host-1", risk_score=50.0)
        trajectories = e.compute_risk_trajectory()
        assert trajectories[0]["trajectory"] == "insufficient_data"

    def test_identify_risk_inflection_points(self) -> None:
        e = self._engine()
        e.add_record(name="t1", entity="host-1", risk_score=10.0)
        e.add_record(name="t2", entity="host-1", risk_score=80.0)
        e.add_record(name="t3", entity="host-1", risk_score=20.0)
        inflections = e.identify_risk_inflection_points()
        assert len(inflections) >= 1
        assert inflections[0]["inflection_type"] == "peak"

    def test_predict_risk_trend_rising(self) -> None:
        e = self._engine()
        e.add_record(name="t1", entity="host-1", risk_score=10.0)
        e.add_record(name="t2", entity="host-1", risk_score=20.0)
        e.add_record(name="t3", entity="host-1", risk_score=40.0)
        preds = e.predict_risk_trend()
        assert preds[0]["predicted_direction"] == "rising"

    def test_predict_risk_trend_insufficient(self) -> None:
        e = self._engine()
        e.add_record(name="t1", entity="host-1", risk_score=50.0)
        preds = e.predict_risk_trend()
        assert preds[0]["predicted_direction"] == "unknown"

    def test_generate_report(self) -> None:
        e = self._engine()
        e.add_record(name="r1", score=80.0)
        report = e.generate_report()
        assert report.total_records == 1

    def test_clear_data(self) -> None:
        e = self._engine()
        e.add_record(name="r1")
        e.clear_data()
        assert e.get_stats()["total_records"] == 0

    def test_process(self) -> None:
        e = self._engine()
        e.add_record(name="test", score=60.0)
        assert e.process("test")["status"] == "processed"

    def test_ring_buffer(self) -> None:
        e = self._engine(max_records=2)
        for i in range(5):
            e.add_record(name=f"r{i}")
        assert len(e._records) == 2


# ============================================================================
# AgentCurriculumEngine
# ============================================================================


class TestCurriculumEnums:
    def test_difficulty_beginner(self) -> None:
        assert DifficultyLevel.BEGINNER == "beginner"

    def test_difficulty_intermediate(self) -> None:
        assert DifficultyLevel.INTERMEDIATE == "intermediate"

    def test_difficulty_advanced(self) -> None:
        assert DifficultyLevel.ADVANCED == "advanced"

    def test_difficulty_expert(self) -> None:
        assert DifficultyLevel.EXPERT == "expert"

    def test_objective_accuracy(self) -> None:
        assert LearningObjective.ACCURACY == "accuracy"

    def test_objective_speed(self) -> None:
        assert LearningObjective.SPEED == "speed"

    def test_objective_cost_efficiency(self) -> None:
        assert LearningObjective.COST_EFFICIENCY == "cost_efficiency"

    def test_objective_coverage(self) -> None:
        assert LearningObjective.COVERAGE == "coverage"

    def test_status_not_started(self) -> None:
        assert CurriculumStatus.NOT_STARTED == "not_started"

    def test_status_in_progress(self) -> None:
        assert CurriculumStatus.IN_PROGRESS == "in_progress"

    def test_status_mastered(self) -> None:
        assert CurriculumStatus.MASTERED == "mastered"

    def test_status_regressed(self) -> None:
        assert CurriculumStatus.REGRESSED == "regressed"


class TestCurriculumModels:
    def test_record_defaults(self) -> None:
        r = AgentCurriculumRecord()
        assert r.id
        assert r.difficulty_level == DifficultyLevel.BEGINNER
        assert r.curriculum_status == CurriculumStatus.NOT_STARTED

    def test_analysis_defaults(self) -> None:
        a = AgentCurriculumAnalysis()
        assert a.breached is False

    def test_report_defaults(self) -> None:
        r = AgentCurriculumReport()
        assert r.total_records == 0


class TestCurriculumEngine:
    def _engine(self, **kw: object) -> AgentCurriculumEngine:
        return AgentCurriculumEngine(**kw)

    def test_add_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="lesson-1", agent_id="agent-a", mastery_pct=50.0)
        assert r.mastery_pct == 50.0

    def test_get_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="l1")
        assert e.get_record(r.id) is not None

    def test_recommend_next_lesson(self) -> None:
        e = self._engine()
        e.add_record(
            name="basics",
            agent_id="agent-a",
            curriculum_status=CurriculumStatus.MASTERED,
        )
        e.add_record(
            name="intermediate",
            agent_id="agent-a",
            curriculum_status=CurriculumStatus.NOT_STARTED,
            difficulty_level=DifficultyLevel.INTERMEDIATE,
        )
        recs = e.recommend_next_lesson()
        assert len(recs) == 1
        assert recs[0]["recommendation"] == "intermediate"

    def test_recommend_next_lesson_all_mastered(self) -> None:
        e = self._engine()
        e.add_record(
            name="l1",
            agent_id="agent-a",
            curriculum_status=CurriculumStatus.MASTERED,
        )
        recs = e.recommend_next_lesson()
        assert recs[0]["recommendation"] == "all_mastered"

    def test_recommend_next_lesson_regressed_priority(self) -> None:
        e = self._engine()
        e.add_record(
            name="l1",
            agent_id="agent-a",
            curriculum_status=CurriculumStatus.REGRESSED,
        )
        e.add_record(
            name="l2",
            agent_id="agent-a",
            curriculum_status=CurriculumStatus.NOT_STARTED,
        )
        recs = e.recommend_next_lesson()
        assert recs[0]["recommendation"] == "l1"

    def test_evaluate_mastery_level(self) -> None:
        e = self._engine()
        e.add_record(name="l1", curriculum_status=CurriculumStatus.MASTERED, mastery_pct=100.0)
        e.add_record(name="l2", curriculum_status=CurriculumStatus.NOT_STARTED, mastery_pct=0.0)
        result = e.evaluate_mastery_level()
        assert result["overall_mastery_pct"] == 50.0
        assert result["total_lessons"] == 2

    def test_evaluate_mastery_level_empty(self) -> None:
        e = self._engine()
        result = e.evaluate_mastery_level()
        assert result["overall_mastery_pct"] == 0.0

    def test_detect_skill_regression(self) -> None:
        e = self._engine()
        e.add_record(
            name="l1",
            agent_id="agent-a",
            curriculum_status=CurriculumStatus.REGRESSED,
        )
        e.add_record(
            name="l2",
            agent_id="agent-a",
            curriculum_status=CurriculumStatus.MASTERED,
        )
        regressions = e.detect_skill_regression()
        assert len(regressions) == 1
        assert regressions[0]["regression_count"] == 1

    def test_detect_skill_regression_none(self) -> None:
        e = self._engine()
        e.add_record(
            name="l1",
            agent_id="agent-a",
            curriculum_status=CurriculumStatus.MASTERED,
        )
        assert e.detect_skill_regression() == []

    def test_generate_report(self) -> None:
        e = self._engine()
        e.add_record(name="r1", score=80.0)
        report = e.generate_report()
        assert report.total_records == 1

    def test_clear_data(self) -> None:
        e = self._engine()
        e.add_record(name="r1")
        e.clear_data()
        assert e.get_stats()["total_records"] == 0

    def test_process(self) -> None:
        e = self._engine()
        e.add_record(name="test", score=60.0)
        assert e.process("test")["status"] == "processed"

    def test_ring_buffer(self) -> None:
        e = self._engine(max_records=2)
        for i in range(5):
            e.add_record(name=f"r{i}")
        assert len(e._records) == 2


# ============================================================================
# ExperimentReplayEngine
# ============================================================================


class TestReplayEnums:
    def test_outcome_confirmed(self) -> None:
        assert ReplayOutcome.CONFIRMED == "confirmed"

    def test_outcome_contradicted(self) -> None:
        assert ReplayOutcome.CONTRADICTED == "contradicted"

    def test_outcome_inconclusive(self) -> None:
        assert ReplayOutcome.INCONCLUSIVE == "inconclusive"

    def test_insight_causal(self) -> None:
        assert InsightType.CAUSAL == "causal"

    def test_insight_correlational(self) -> None:
        assert InsightType.CORRELATIONAL == "correlational"

    def test_insight_spurious(self) -> None:
        assert InsightType.SPURIOUS == "spurious"

    def test_strategy_exact(self) -> None:
        assert ReplayStrategy.EXACT == "exact"

    def test_strategy_perturbed(self) -> None:
        assert ReplayStrategy.PERTURBED == "perturbed"

    def test_strategy_counterfactual(self) -> None:
        assert ReplayStrategy.COUNTERFACTUAL == "counterfactual"


class TestReplayModels:
    def test_record_defaults(self) -> None:
        r = ExperimentReplayRecord()
        assert r.id
        assert r.replay_outcome == ReplayOutcome.INCONCLUSIVE
        assert r.insight_type == InsightType.CORRELATIONAL

    def test_analysis_defaults(self) -> None:
        a = ExperimentReplayAnalysis()
        assert a.breached is False

    def test_report_defaults(self) -> None:
        r = ExperimentReplayReport()
        assert r.total_records == 0


class TestReplayEngine:
    def _engine(self, **kw: object) -> ExperimentReplayEngine:
        return ExperimentReplayEngine(**kw)

    def test_add_record(self) -> None:
        e = self._engine()
        r = e.add_record(
            name="replay-1",
            experiment_id="exp-1",
            original_score=80.0,
            replay_score=75.0,
        )
        assert r.experiment_id == "exp-1"

    def test_get_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="r1")
        assert e.get_record(r.id) is not None

    def test_identify_replayable_experiments(self) -> None:
        e = self._engine()
        e.add_record(
            name="r1",
            experiment_id="exp-1",
            replay_outcome=ReplayOutcome.INCONCLUSIVE,
            score=30.0,
        )
        replayable = e.identify_replayable_experiments()
        assert len(replayable) == 1
        assert replayable[0]["replayability"] == "high"

    def test_analyze_replay_divergence(self) -> None:
        e = self._engine()
        e.add_record(
            name="r1",
            original_score=80.0,
            replay_score=50.0,
        )
        divergences = e.analyze_replay_divergence()
        assert len(divergences) == 1
        assert divergences[0]["delta"] == 30.0
        assert divergences[0]["divergence"] == "high"

    def test_analyze_replay_divergence_low(self) -> None:
        e = self._engine()
        e.add_record(name="r1", original_score=80.0, replay_score=78.0)
        divergences = e.analyze_replay_divergence()
        assert divergences[0]["divergence"] == "low"

    def test_extract_meta_insights(self) -> None:
        e = self._engine()
        e.add_record(
            name="r1",
            insight_type=InsightType.CAUSAL,
            replay_outcome=ReplayOutcome.CONFIRMED,
            score=80.0,
        )
        e.add_record(
            name="r2",
            insight_type=InsightType.SPURIOUS,
            replay_outcome=ReplayOutcome.CONTRADICTED,
            score=20.0,
        )
        insights = e.extract_meta_insights()
        assert "causal" in insights
        assert insights["causal"]["reliability"] == "high"

    def test_generate_report(self) -> None:
        e = self._engine()
        e.add_record(name="r1", score=80.0)
        report = e.generate_report()
        assert report.total_records == 1

    def test_clear_data(self) -> None:
        e = self._engine()
        e.add_record(name="r1")
        e.clear_data()
        assert e.get_stats()["total_records"] == 0

    def test_process(self) -> None:
        e = self._engine()
        e.add_record(name="test", score=60.0)
        assert e.process("test")["status"] == "processed"

    def test_ring_buffer(self) -> None:
        e = self._engine(max_records=2)
        for i in range(5):
            e.add_record(name=f"r{i}")
        assert len(e._records) == 2

    def test_list_records_filter(self) -> None:
        e = self._engine()
        e.add_record(name="r1", replay_outcome=ReplayOutcome.CONFIRMED)
        e.add_record(name="r2", replay_outcome=ReplayOutcome.CONTRADICTED)
        results = e.list_records(replay_outcome=ReplayOutcome.CONFIRMED)
        assert len(results) == 1


# ============================================================================
# ResourceEfficiencyOptimizerEngine
# ============================================================================


class TestResourceEnums:
    def test_type_llm_tokens(self) -> None:
        assert ResourceType.LLM_TOKENS == "llm_tokens"

    def test_type_compute(self) -> None:
        assert ResourceType.COMPUTE_SECONDS == "compute_seconds"

    def test_type_memory(self) -> None:
        assert ResourceType.MEMORY_MB == "memory_mb"

    def test_type_api_calls(self) -> None:
        assert ResourceType.API_CALLS == "api_calls"

    def test_goal_minimize(self) -> None:
        assert OptimizationGoal.MINIMIZE_COST == "minimize_cost"

    def test_goal_maximize(self) -> None:
        assert OptimizationGoal.MAXIMIZE_THROUGHPUT == "maximize_throughput"

    def test_goal_balance(self) -> None:
        assert OptimizationGoal.BALANCE == "balance"

    def test_trend_improving(self) -> None:
        assert EfficiencyTrend.IMPROVING == "improving"

    def test_trend_degrading(self) -> None:
        assert EfficiencyTrend.DEGRADING == "degrading"

    def test_trend_plateau(self) -> None:
        assert EfficiencyTrend.PLATEAU == "plateau"


class TestResourceModels:
    def test_record_defaults(self) -> None:
        r = ResourceEfficiencyOptimizerRecord()
        assert r.id
        assert r.resource_type == ResourceType.LLM_TOKENS
        assert r.cost_usd == 0.0

    def test_analysis_defaults(self) -> None:
        a = ResourceEfficiencyOptimizerAnalysis()
        assert a.breached is False

    def test_report_defaults(self) -> None:
        r = ResourceEfficiencyOptimizerReport()
        assert r.total_records == 0


class TestResourceEngine:
    def _engine(self, **kw: object) -> ResourceEfficiencyOptimizerEngine:
        return ResourceEfficiencyOptimizerEngine(**kw)

    def test_add_record(self) -> None:
        e = self._engine()
        r = e.add_record(
            name="token-usage",
            agent_id="agent-a",
            resource_used=1000.0,
            resource_budget=2000.0,
            cost_usd=0.5,
        )
        assert r.resource_used == 1000.0

    def test_get_record(self) -> None:
        e = self._engine()
        r = e.add_record(name="r1")
        assert e.get_record(r.id) is not None

    def test_identify_resource_waste(self) -> None:
        e = self._engine()
        e.add_record(
            name="r1",
            agent_id="agent-a",
            score=30.0,
            cost_usd=10.0,
            resource_used=900.0,
            resource_budget=1000.0,
        )
        waste = e.identify_resource_waste()
        assert len(waste) == 1
        assert waste[0]["waste_severity"] in ("moderate", "high")

    def test_identify_resource_waste_high(self) -> None:
        e = self._engine()
        e.add_record(
            name="r1",
            agent_id="agent-a",
            score=10.0,
            cost_usd=50.0,
        )
        waste = e.identify_resource_waste()
        assert waste[0]["waste_severity"] == "high"

    def test_propose_efficiency_improvements_degrading(self) -> None:
        e = self._engine()
        e.add_record(
            name="r1",
            efficiency_trend=EfficiencyTrend.DEGRADING,
            cost_usd=5.0,
        )
        improvements = e.propose_efficiency_improvements()
        assert len(improvements) >= 1
        assert any(i["issue"] == "degrading_efficiency" for i in improvements)

    def test_propose_efficiency_improvements_over_budget(self) -> None:
        e = self._engine()
        e.add_record(
            name="r1",
            resource_used=200.0,
            resource_budget=100.0,
        )
        improvements = e.propose_efficiency_improvements()
        assert any(i["issue"] == "over_budget" for i in improvements)

    def test_compute_cost_per_outcome(self) -> None:
        e = self._engine()
        e.add_record(name="r1", agent_id="agent-a", score=80.0, cost_usd=4.0)
        results = e.compute_cost_per_outcome()
        assert len(results) == 1
        assert results[0]["cost_per_score_point"] == 0.05

    def test_compute_cost_per_outcome_zero_score(self) -> None:
        e = self._engine()
        e.add_record(name="r1", agent_id="agent-a", score=0.0, cost_usd=4.0)
        results = e.compute_cost_per_outcome()
        assert results[0]["cost_per_score_point"] == 0.0

    def test_generate_report(self) -> None:
        e = self._engine()
        e.add_record(name="r1", score=80.0)
        report = e.generate_report()
        assert report.total_records == 1

    def test_generate_report_with_gaps(self) -> None:
        e = self._engine()
        e.add_record(name="r1", score=20.0)
        report = e.generate_report()
        assert report.gap_count == 1

    def test_clear_data(self) -> None:
        e = self._engine()
        e.add_record(name="r1")
        e.clear_data()
        assert e.get_stats()["total_records"] == 0

    def test_get_stats(self) -> None:
        e = self._engine()
        e.add_record(name="r1", team="t1", service="svc-a")
        stats = e.get_stats()
        assert stats["unique_teams"] == 1

    def test_process(self) -> None:
        e = self._engine()
        e.add_record(name="test", score=60.0)
        assert e.process("test")["status"] == "processed"

    def test_process_not_found(self) -> None:
        e = self._engine()
        assert e.process("missing")["status"] == "not_found"

    def test_ring_buffer(self) -> None:
        e = self._engine(max_records=2)
        for i in range(5):
            e.add_record(name=f"r{i}")
        assert len(e._records) == 2

    def test_analyze_distribution(self) -> None:
        e = self._engine()
        e.add_record(name="r1", resource_type=ResourceType.LLM_TOKENS, score=70.0)
        dist = e.analyze_distribution()
        assert "llm_tokens" in dist

    def test_identify_gaps(self) -> None:
        e = self._engine()
        e.add_record(name="low", score=10.0)
        gaps = e.identify_gaps()
        assert len(gaps) == 1

    def test_rank_by_score(self) -> None:
        e = self._engine()
        e.add_record(name="r1", service="svc-a", score=90.0)
        e.add_record(name="r2", service="svc-b", score=30.0)
        ranked = e.rank_by_score()
        assert ranked[0]["service"] == "svc-b"

    def test_list_records_filter(self) -> None:
        e = self._engine()
        e.add_record(name="r1", resource_type=ResourceType.LLM_TOKENS)
        e.add_record(name="r2", resource_type=ResourceType.MEMORY_MB)
        results = e.list_records(resource_type=ResourceType.LLM_TOKENS)
        assert len(results) == 1
