"""Tests for Phase 138 engines (detection lifecycle, MITRE coverage, prompt optimizer,
continuous improvement, fleet intelligence)."""

from __future__ import annotations

from shieldops.analytics.agent_prompt_optimizer_engine import (
    AgentPromptOptimizerAnalysis,
    AgentPromptOptimizerEngine,
    AgentPromptOptimizerRecord,
    AgentPromptOptimizerReport,
    OptimizationMetric,
    PromptStatus,
    PromptVariant,
)
from shieldops.analytics.continuous_improvement_engine import (
    ContinuousImprovementAnalysis,
    ContinuousImprovementEngine,
    ContinuousImprovementRecord,
    ContinuousImprovementReport,
    CyclePhase,
    ImprovementArea,
    ImprovementStatus,
)
from shieldops.analytics.fleet_intelligence_engine import (
    FleetHealth,
    FleetIntelligenceAnalysis,
    FleetIntelligenceEngine,
    FleetIntelligenceRecord,
    FleetIntelligenceReport,
    FleetMetric,
    StrategicInsight,
)
from shieldops.security.detection_rule_lifecycle_engine import (
    DetectionRuleLifecycleAnalysis,
    DetectionRuleLifecycleEngine,
    DetectionRuleLifecycleRecord,
    DetectionRuleLifecycleReport,
    MaintenanceAction,
    RuleLifecyclePhase,
    RuleQuality,
)
from shieldops.security.mitre_coverage_tracker_engine import (
    CoverageChange,
    CoverageLevel,
    MitreCoverageTrackerAnalysis,
    MitreCoverageTrackerEngine,
    MitreCoverageTrackerRecord,
    MitreCoverageTrackerReport,
    TacticPriority,
)

# =============================================================================
# DetectionRuleLifecycleEngine Tests
# =============================================================================


class TestDetectionRuleLifecycleEnums:
    def test_rule_lifecycle_phase_values(self):
        assert RuleLifecyclePhase.DRAFT == "draft"
        assert RuleLifecyclePhase.TESTING == "testing"
        assert RuleLifecyclePhase.ACTIVE == "active"
        assert RuleLifecyclePhase.TUNING == "tuning"
        assert RuleLifecyclePhase.DEPRECATED == "deprecated"
        assert RuleLifecyclePhase.RETIRED == "retired"

    def test_rule_quality_values(self):
        assert RuleQuality.EXCELLENT == "excellent"
        assert RuleQuality.GOOD == "good"
        assert RuleQuality.FAIR == "fair"
        assert RuleQuality.POOR == "poor"

    def test_maintenance_action_values(self):
        assert MaintenanceAction.TUNE == "tune"
        assert MaintenanceAction.REWRITE == "rewrite"
        assert MaintenanceAction.RETIRE == "retire"
        assert MaintenanceAction.PROMOTE == "promote"


class TestDetectionRuleLifecycleModels:
    def test_record_defaults(self):
        r = DetectionRuleLifecycleRecord()
        assert r.rule_lifecycle_phase == RuleLifecyclePhase.DRAFT
        assert r.true_positives == 0

    def test_analysis_defaults(self):
        a = DetectionRuleLifecycleAnalysis()
        assert a.analysis_score == 0.0

    def test_report_defaults(self):
        rp = DetectionRuleLifecycleReport()
        assert rp.total_records == 0


class TestDetectionRuleLifecycleEngine:
    def setup_method(self):
        self.engine = DetectionRuleLifecycleEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._max_records == 100

    def test_add_record(self):
        r = self.engine.add_record(name="rule-1", score=75.0, service="svc-a")
        assert r.name == "rule-1"

    def test_get_record(self):
        r = self.engine.add_record(name="rule-1")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self):
        assert self.engine.get_record("nope") is None

    def test_list_records_filter(self):
        self.engine.add_record(name="a", rule_lifecycle_phase=RuleLifecyclePhase.ACTIVE)
        self.engine.add_record(name="b", rule_lifecycle_phase=RuleLifecyclePhase.DRAFT)
        results = self.engine.list_records(rule_lifecycle_phase=RuleLifecyclePhase.ACTIVE)
        assert len(results) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="test")
        assert a.name == "test"

    def test_ring_buffer(self):
        engine = DetectionRuleLifecycleEngine(max_records=3)
        for i in range(7):
            engine.add_record(name=f"r{i}")
        assert len(engine._records) == 3

    def test_identify_stale_rules(self):
        self.engine.add_record(name="stale", days_since_update=200, service="svc-a")
        self.engine.add_record(name="fresh", days_since_update=10, service="svc-b")
        stale = self.engine.identify_stale_rules()
        assert len(stale) == 1
        assert stale[0]["name"] == "stale"
        assert stale[0]["recommendation"] == "review"

    def test_identify_stale_rules_retire(self):
        self.engine.add_record(name="ancient", days_since_update=400)
        stale = self.engine.identify_stale_rules()
        assert stale[0]["recommendation"] == "retire"

    def test_identify_stale_rules_empty(self):
        assert self.engine.identify_stale_rules() == []

    def test_compute_rule_quality_score(self):
        self.engine.add_record(name="rule-a", true_positives=90, false_positives=10, score=80.0)
        results = self.engine.compute_rule_quality_score()
        assert len(results) == 1
        assert results[0]["precision"] == 0.9
        assert results[0]["quality_label"] == "excellent"

    def test_compute_rule_quality_score_poor(self):
        self.engine.add_record(name="rule-bad", true_positives=10, false_positives=90)
        results = self.engine.compute_rule_quality_score()
        assert results[0]["quality_label"] == "poor"

    def test_compute_rule_quality_score_zero(self):
        self.engine.add_record(name="rule-zero", true_positives=0, false_positives=0)
        results = self.engine.compute_rule_quality_score()
        assert results[0]["precision"] == 0.0

    def test_recommend_maintenance_actions_poor_quality(self):
        self.engine.add_record(name="bad", rule_quality=RuleQuality.POOR)
        recs = self.engine.recommend_maintenance_actions()
        assert len(recs) == 1
        assert recs[0]["action"] == "rewrite"
        assert recs[0]["priority"] == "high"

    def test_recommend_maintenance_actions_deprecated(self):
        self.engine.add_record(
            name="old",
            rule_lifecycle_phase=RuleLifecyclePhase.DEPRECATED,
            rule_quality=RuleQuality.GOOD,
        )
        recs = self.engine.recommend_maintenance_actions()
        assert recs[0]["action"] == "retire"

    def test_recommend_maintenance_actions_stale_fair(self):
        self.engine.add_record(
            name="stale-fair",
            rule_quality=RuleQuality.FAIR,
            days_since_update=200,
            score=60.0,
        )
        recs = self.engine.recommend_maintenance_actions()
        assert recs[0]["action"] == "tune"

    def test_recommend_maintenance_actions_low_score(self):
        self.engine.add_record(
            name="low",
            rule_quality=RuleQuality.GOOD,
            score=10.0,
        )
        recs = self.engine.recommend_maintenance_actions()
        assert recs[0]["issue"] == "low_score"

    def test_process(self):
        self.engine.add_record(name="key1", score=60.0)
        result = self.engine.process("key1")
        assert result["status"] == "processed"

    def test_generate_report(self):
        self.engine.add_record(name="a", score=30.0)
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_get_stats(self):
        self.engine.add_record(name="a", service="s1", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1

    def test_clear_data(self):
        self.engine.add_record(name="a")
        self.engine.clear_data()
        assert len(self.engine._records) == 0


# =============================================================================
# MitreCoverageTrackerEngine Tests
# =============================================================================


class TestMitreCoverageTrackerEnums:
    def test_coverage_level_values(self):
        assert CoverageLevel.NONE == "none"
        assert CoverageLevel.BASIC == "basic"
        assert CoverageLevel.MODERATE == "moderate"
        assert CoverageLevel.COMPREHENSIVE == "comprehensive"

    def test_tactic_priority_values(self):
        assert TacticPriority.CRITICAL == "critical"
        assert TacticPriority.HIGH == "high"

    def test_coverage_change_values(self):
        assert CoverageChange.IMPROVED == "improved"
        assert CoverageChange.UNCHANGED == "unchanged"
        assert CoverageChange.DEGRADED == "degraded"


class TestMitreCoverageTrackerModels:
    def test_record_defaults(self):
        r = MitreCoverageTrackerRecord()
        assert r.coverage_level == CoverageLevel.NONE
        assert r.technique_count == 0

    def test_analysis_defaults(self):
        a = MitreCoverageTrackerAnalysis()
        assert a.analysis_score == 0.0

    def test_report_defaults(self):
        rp = MitreCoverageTrackerReport()
        assert rp.total_records == 0


class TestMitreCoverageTrackerEngine:
    def setup_method(self):
        self.engine = MitreCoverageTrackerEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._max_records == 100

    def test_add_record(self):
        r = self.engine.add_record(name="TA0001", tactic_id="TA0001", score=60.0)
        assert r.name == "TA0001"

    def test_get_record(self):
        r = self.engine.add_record(name="TA0001")
        assert self.engine.get_record(r.id) is not None

    def test_list_records_filter(self):
        self.engine.add_record(name="a", coverage_level=CoverageLevel.COMPREHENSIVE)
        self.engine.add_record(name="b", coverage_level=CoverageLevel.NONE)
        results = self.engine.list_records(coverage_level=CoverageLevel.NONE)
        assert len(results) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="test")
        assert a.name == "test"

    def test_compute_tactic_coverage(self):
        self.engine.add_record(
            name="a", tactic_id="TA0001", technique_count=20, covered_techniques=15, score=70.0
        )
        results = self.engine.compute_tactic_coverage()
        assert len(results) == 1
        assert results[0]["coverage_pct"] == 75.0

    def test_compute_tactic_coverage_zero(self):
        self.engine.add_record(
            name="a", tactic_id="TA0001", technique_count=0, covered_techniques=0
        )
        results = self.engine.compute_tactic_coverage()
        assert results[0]["coverage_pct"] == 0.0

    def test_identify_coverage_regressions(self):
        self.engine.add_record(
            name="a",
            tactic_id="TA0001",
            coverage_change=CoverageChange.DEGRADED,
            tactic_priority=TacticPriority.CRITICAL,
        )
        self.engine.add_record(
            name="b",
            tactic_id="TA0002",
            coverage_change=CoverageChange.IMPROVED,
        )
        regressions = self.engine.identify_coverage_regressions()
        assert len(regressions) == 1
        assert regressions[0]["severity"] == "critical"

    def test_identify_coverage_regressions_high(self):
        self.engine.add_record(
            name="a",
            coverage_change=CoverageChange.DEGRADED,
            tactic_priority=TacticPriority.HIGH,
        )
        regressions = self.engine.identify_coverage_regressions()
        assert regressions[0]["severity"] == "high"

    def test_identify_coverage_regressions_empty(self):
        assert self.engine.identify_coverage_regressions() == []

    def test_prioritize_coverage_investments(self):
        self.engine.add_record(
            name="a",
            tactic_id="TA0001",
            technique_count=20,
            covered_techniques=5,
            tactic_priority=TacticPriority.CRITICAL,
        )
        investments = self.engine.prioritize_coverage_investments()
        assert len(investments) == 1
        assert investments[0]["uncovered_techniques"] == 15

    def test_prioritize_coverage_investments_full(self):
        self.engine.add_record(
            name="a",
            tactic_id="TA0001",
            technique_count=10,
            covered_techniques=10,
            tactic_priority=TacticPriority.LOW,
        )
        investments = self.engine.prioritize_coverage_investments()
        assert len(investments) == 0

    def test_process(self):
        self.engine.add_record(name="key1", score=60.0)
        result = self.engine.process("key1")
        assert result["status"] == "processed"

    def test_generate_report(self):
        self.engine.add_record(name="a", score=30.0)
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_get_stats(self):
        self.engine.add_record(name="a", service="s1", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1

    def test_clear_data(self):
        self.engine.add_record(name="a")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_rank_by_score(self):
        self.engine.add_record(name="a", service="low", score=10.0)
        self.engine.add_record(name="b", service="high", score=90.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "low"


# =============================================================================
# AgentPromptOptimizerEngine Tests
# =============================================================================


class TestAgentPromptOptimizerEnums:
    def test_prompt_variant_values(self):
        assert PromptVariant.BASELINE == "baseline"
        assert PromptVariant.CANDIDATE_A == "candidate_a"
        assert PromptVariant.CANDIDATE_B == "candidate_b"
        assert PromptVariant.CHAMPION == "champion"

    def test_optimization_metric_values(self):
        assert OptimizationMetric.ACCURACY == "accuracy"
        assert OptimizationMetric.LATENCY == "latency"
        assert OptimizationMetric.TOKEN_COST == "token_cost"
        assert OptimizationMetric.USER_SATISFACTION == "user_satisfaction"

    def test_prompt_status_values(self):
        assert PromptStatus.TESTING == "testing"
        assert PromptStatus.CHAMPION == "champion"
        assert PromptStatus.RETIRED == "retired"


class TestAgentPromptOptimizerModels:
    def test_record_defaults(self):
        r = AgentPromptOptimizerRecord()
        assert r.prompt_variant == PromptVariant.BASELINE
        assert r.token_count == 0

    def test_analysis_defaults(self):
        a = AgentPromptOptimizerAnalysis()
        assert a.analysis_score == 0.0

    def test_report_defaults(self):
        rp = AgentPromptOptimizerReport()
        assert rp.total_records == 0


class TestAgentPromptOptimizerEngine:
    def setup_method(self):
        self.engine = AgentPromptOptimizerEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._max_records == 100

    def test_add_record(self):
        r = self.engine.add_record(name="prompt-v1", score=80.0, service="svc-a")
        assert r.name == "prompt-v1"

    def test_get_record(self):
        r = self.engine.add_record(name="p1")
        assert self.engine.get_record(r.id) is not None

    def test_list_records_filter(self):
        self.engine.add_record(name="a", prompt_variant=PromptVariant.BASELINE)
        self.engine.add_record(name="b", prompt_variant=PromptVariant.CHAMPION)
        results = self.engine.list_records(prompt_variant=PromptVariant.CHAMPION)
        assert len(results) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="test")
        assert a.name == "test"

    def test_evaluate_prompt_variants(self):
        self.engine.add_record(
            name="a",
            prompt_variant=PromptVariant.BASELINE,
            score=60.0,
            token_count=500,
            invocation_count=10,
        )
        self.engine.add_record(
            name="b",
            prompt_variant=PromptVariant.CHAMPION,
            score=90.0,
            token_count=300,
            invocation_count=10,
        )
        results = self.engine.evaluate_prompt_variants()
        assert len(results) == 2
        assert results[0]["variant"] == "champion"

    def test_evaluate_prompt_variants_empty(self):
        assert self.engine.evaluate_prompt_variants() == []

    def test_identify_winning_prompts(self):
        self.engine.add_record(
            name="a", prompt_variant=PromptVariant.BASELINE, score=60.0, service="svc-a"
        )
        self.engine.add_record(
            name="b", prompt_variant=PromptVariant.CHAMPION, score=90.0, service="svc-a"
        )
        winners = self.engine.identify_winning_prompts()
        assert len(winners) == 1
        assert winners[0]["winning_variant"] == "champion"

    def test_identify_winning_prompts_empty(self):
        assert self.engine.identify_winning_prompts() == []

    def test_compute_prompt_roi(self):
        self.engine.add_record(
            name="baseline",
            prompt_variant=PromptVariant.BASELINE,
            score=50.0,
            token_count=1000,
            service="svc-a",
        )
        self.engine.add_record(
            name="champion",
            prompt_variant=PromptVariant.CHAMPION,
            score=80.0,
            token_count=800,
            service="svc-a",
        )
        roi = self.engine.compute_prompt_roi()
        assert len(roi) == 1
        assert roi[0]["score_improvement"] == 30.0
        assert roi[0]["roi_positive"] is True

    def test_compute_prompt_roi_no_champion(self):
        self.engine.add_record(
            name="baseline",
            prompt_variant=PromptVariant.BASELINE,
            score=50.0,
            service="svc-a",
        )
        roi = self.engine.compute_prompt_roi()
        assert len(roi) == 0

    def test_process(self):
        self.engine.add_record(name="key1", score=60.0)
        result = self.engine.process("key1")
        assert result["status"] == "processed"

    def test_generate_report(self):
        self.engine.add_record(name="a", score=30.0)
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_get_stats(self):
        self.engine.add_record(name="a", service="s1", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1

    def test_clear_data(self):
        self.engine.add_record(name="a")
        self.engine.clear_data()
        assert len(self.engine._records) == 0


# =============================================================================
# ContinuousImprovementEngine Tests
# =============================================================================


class TestContinuousImprovementEnums:
    def test_improvement_area_values(self):
        assert ImprovementArea.ACCURACY == "accuracy"
        assert ImprovementArea.SPEED == "speed"
        assert ImprovementArea.COST == "cost"
        assert ImprovementArea.COVERAGE == "coverage"
        assert ImprovementArea.RELIABILITY == "reliability"

    def test_cycle_phase_values(self):
        assert CyclePhase.MEASURE == "measure"
        assert CyclePhase.ANALYZE == "analyze"
        assert CyclePhase.IMPROVE == "improve"
        assert CyclePhase.CONTROL == "control"

    def test_improvement_status_values(self):
        assert ImprovementStatus.IN_PROGRESS == "in_progress"
        assert ImprovementStatus.COMPLETED == "completed"
        assert ImprovementStatus.STALLED == "stalled"
        assert ImprovementStatus.REGRESSED == "regressed"


class TestContinuousImprovementModels:
    def test_record_defaults(self):
        r = ContinuousImprovementRecord()
        assert r.improvement_area == ImprovementArea.ACCURACY
        assert r.baseline_value == 0.0

    def test_analysis_defaults(self):
        a = ContinuousImprovementAnalysis()
        assert a.analysis_score == 0.0

    def test_report_defaults(self):
        rp = ContinuousImprovementReport()
        assert rp.total_records == 0


class TestContinuousImprovementEngine:
    def setup_method(self):
        self.engine = ContinuousImprovementEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._max_records == 100

    def test_add_record(self):
        r = self.engine.add_record(name="imp-1", score=70.0, service="svc-a")
        assert r.name == "imp-1"

    def test_get_record(self):
        r = self.engine.add_record(name="imp-1")
        assert self.engine.get_record(r.id) is not None

    def test_list_records_filter(self):
        self.engine.add_record(name="a", improvement_area=ImprovementArea.ACCURACY)
        self.engine.add_record(name="b", improvement_area=ImprovementArea.COST)
        results = self.engine.list_records(improvement_area=ImprovementArea.COST)
        assert len(results) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="test")
        assert a.name == "test"

    def test_measure_improvement_velocity(self):
        self.engine.add_record(
            name="a",
            improvement_area=ImprovementArea.ACCURACY,
            improvement_status=ImprovementStatus.COMPLETED,
            baseline_value=0.5,
            current_value=0.9,
            target_value=1.0,
        )
        results = self.engine.measure_improvement_velocity()
        assert len(results) == 1
        assert results[0]["completion_rate"] == 1.0
        assert results[0]["avg_velocity"] > 0

    def test_measure_improvement_velocity_empty(self):
        assert self.engine.measure_improvement_velocity() == []

    def test_measure_improvement_velocity_no_progress(self):
        self.engine.add_record(
            name="a",
            improvement_area=ImprovementArea.SPEED,
            improvement_status=ImprovementStatus.IN_PROGRESS,
            baseline_value=0.5,
            current_value=0.5,
            target_value=1.0,
        )
        results = self.engine.measure_improvement_velocity()
        assert results[0]["avg_velocity"] == 0.0

    def test_identify_stalled_improvements(self):
        self.engine.add_record(
            name="stalled-1",
            improvement_status=ImprovementStatus.STALLED,
            baseline_value=0.0,
            current_value=0.3,
            target_value=1.0,
            service="svc-a",
        )
        self.engine.add_record(
            name="ok",
            improvement_status=ImprovementStatus.COMPLETED,
        )
        stalled = self.engine.identify_stalled_improvements()
        assert len(stalled) == 1
        assert stalled[0]["name"] == "stalled-1"
        assert stalled[0]["progress"] == 0.3

    def test_identify_stalled_improvements_empty(self):
        assert self.engine.identify_stalled_improvements() == []

    def test_recommend_next_improvement_regressed(self):
        self.engine.add_record(
            name="reg",
            service="svc-a",
            improvement_status=ImprovementStatus.REGRESSED,
            improvement_area=ImprovementArea.ACCURACY,
        )
        recs = self.engine.recommend_next_improvement()
        assert len(recs) == 1
        assert recs[0]["priority"] == "critical"

    def test_recommend_next_improvement_stalled(self):
        self.engine.add_record(
            name="stall",
            service="svc-a",
            improvement_status=ImprovementStatus.STALLED,
            improvement_area=ImprovementArea.SPEED,
        )
        recs = self.engine.recommend_next_improvement()
        assert recs[0]["priority"] == "high"

    def test_recommend_next_improvement_in_progress(self):
        self.engine.add_record(
            name="prog",
            service="svc-a",
            improvement_status=ImprovementStatus.IN_PROGRESS,
            improvement_area=ImprovementArea.COST,
        )
        recs = self.engine.recommend_next_improvement()
        assert recs[0]["priority"] == "medium"

    def test_recommend_next_improvement_empty(self):
        assert self.engine.recommend_next_improvement() == []

    def test_process(self):
        self.engine.add_record(name="key1", score=60.0)
        result = self.engine.process("key1")
        assert result["status"] == "processed"

    def test_generate_report(self):
        self.engine.add_record(name="a", score=30.0)
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_get_stats(self):
        self.engine.add_record(name="a", service="s1", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1

    def test_clear_data(self):
        self.engine.add_record(name="a")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_rank_by_score(self):
        self.engine.add_record(name="a", service="low", score=10.0)
        self.engine.add_record(name="b", service="high", score=90.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "low"

    def test_identify_gaps(self):
        self.engine.add_record(name="low", score=10.0)
        self.engine.add_record(name="high", score=90.0)
        gaps = self.engine.identify_gaps()
        assert len(gaps) == 1


# =============================================================================
# FleetIntelligenceEngine Tests
# =============================================================================


class TestFleetIntelligenceEnums:
    def test_fleet_metric_values(self):
        assert FleetMetric.TOTAL_INVOCATIONS == "total_invocations"
        assert FleetMetric.SUCCESS_RATE == "success_rate"
        assert FleetMetric.AVG_LATENCY == "avg_latency"
        assert FleetMetric.COST_PER_RESOLUTION == "cost_per_resolution"

    def test_fleet_health_values(self):
        assert FleetHealth.THRIVING == "thriving"
        assert FleetHealth.STABLE == "stable"
        assert FleetHealth.DECLINING == "declining"
        assert FleetHealth.CRITICAL == "critical"

    def test_strategic_insight_values(self):
        assert StrategicInsight.SCALE_UP == "scale_up"
        assert StrategicInsight.OPTIMIZE == "optimize"
        assert StrategicInsight.CONSOLIDATE == "consolidate"
        assert StrategicInsight.RETRAIN == "retrain"


class TestFleetIntelligenceModels:
    def test_record_defaults(self):
        r = FleetIntelligenceRecord()
        assert r.fleet_metric == FleetMetric.TOTAL_INVOCATIONS
        assert r.invocations == 0

    def test_analysis_defaults(self):
        a = FleetIntelligenceAnalysis()
        assert a.analysis_score == 0.0

    def test_report_defaults(self):
        rp = FleetIntelligenceReport()
        assert rp.total_records == 0


class TestFleetIntelligenceEngine:
    def setup_method(self):
        self.engine = FleetIntelligenceEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._max_records == 100

    def test_add_record(self):
        r = self.engine.add_record(name="agent-1", score=80.0, service="svc-a")
        assert r.name == "agent-1"

    def test_get_record(self):
        r = self.engine.add_record(name="a1")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self):
        assert self.engine.get_record("nope") is None

    def test_list_records_filter(self):
        self.engine.add_record(name="a", fleet_health=FleetHealth.THRIVING)
        self.engine.add_record(name="b", fleet_health=FleetHealth.CRITICAL)
        results = self.engine.list_records(fleet_health=FleetHealth.CRITICAL)
        assert len(results) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="test")
        assert a.name == "test"

    def test_ring_buffer(self):
        engine = FleetIntelligenceEngine(max_records=3)
        for i in range(7):
            engine.add_record(name=f"r{i}")
        assert len(engine._records) == 3

    def test_compute_fleet_health(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            score=80.0,
            invocations=100,
            success_count=90,
            failure_count=10,
            cost=50.0,
        )
        results = self.engine.compute_fleet_health()
        assert len(results) == 1
        assert results[0]["success_rate"] == 0.9

    def test_compute_fleet_health_zero_counts(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            success_count=0,
            failure_count=0,
        )
        results = self.engine.compute_fleet_health()
        assert results[0]["success_rate"] == 0.0

    def test_compute_fleet_health_empty(self):
        assert self.engine.compute_fleet_health() == []

    def test_identify_underperforming_agents(self):
        self.engine.add_record(name="a", service="svc-good", score=90.0)
        self.engine.add_record(name="b", service="svc-bad", score=20.0)
        underperforming = self.engine.identify_underperforming_agents()
        assert len(underperforming) == 1
        assert underperforming[0]["service"] == "svc-bad"

    def test_identify_underperforming_agents_empty(self):
        assert self.engine.identify_underperforming_agents() == []

    def test_identify_underperforming_agents_critical(self):
        self.engine.add_record(
            name="a", service="svc-good", score=90.0, fleet_health=FleetHealth.THRIVING
        )
        self.engine.add_record(
            name="b", service="svc-bad", score=20.0, fleet_health=FleetHealth.CRITICAL
        )
        underperforming = self.engine.identify_underperforming_agents()
        assert underperforming[0]["severity"] == "critical"

    def test_recommend_fleet_strategy_retrain(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            score=80.0,
            success_count=30,
            failure_count=70,
        )
        recs = self.engine.recommend_fleet_strategy()
        assert len(recs) == 1
        assert recs[0]["strategy"] == "retrain"
        assert recs[0]["priority"] == "critical"

    def test_recommend_fleet_strategy_optimize(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            score=30.0,
            success_count=80,
            failure_count=20,
        )
        recs = self.engine.recommend_fleet_strategy()
        assert recs[0]["strategy"] == "optimize"

    def test_recommend_fleet_strategy_consolidate(self):
        self.engine.add_record(
            name="a",
            service="svc-a",
            score=80.0,
            success_count=100,
            failure_count=5,
            cost=5000.0,
        )
        recs = self.engine.recommend_fleet_strategy()
        assert len(recs) == 1
        assert recs[0]["strategy"] == "consolidate"

    def test_recommend_fleet_strategy_empty(self):
        assert self.engine.recommend_fleet_strategy() == []

    def test_process(self):
        self.engine.add_record(name="key1", score=60.0)
        result = self.engine.process("key1")
        assert result["status"] == "processed"

    def test_process_not_found(self):
        result = self.engine.process("missing")
        assert result["status"] == "not_found"

    def test_generate_report(self):
        self.engine.add_record(name="a", score=30.0)
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_generate_report_healthy(self):
        self.engine.add_record(name="a", score=90.0)
        report = self.engine.generate_report()
        assert "healthy" in report.recommendations[0].lower()

    def test_get_stats(self):
        self.engine.add_record(name="a", service="s1", team="t1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1

    def test_clear_data(self):
        self.engine.add_record(name="a")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_rank_by_score(self):
        self.engine.add_record(name="a", service="low", score=10.0)
        self.engine.add_record(name="b", service="high", score=90.0)
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "low"

    def test_identify_gaps(self):
        self.engine.add_record(name="low", score=10.0)
        self.engine.add_record(name="high", score=90.0)
        gaps = self.engine.identify_gaps()
        assert len(gaps) == 1

    def test_analyze_distribution(self):
        self.engine.add_record(name="a", fleet_metric=FleetMetric.TOTAL_INVOCATIONS, score=80.0)
        dist = self.engine.analyze_distribution()
        assert "total_invocations" in dist
