"""Tests for Phase 136 engines 4-8: Security Posture, Threat Simulation, Meta Learning,
Autonomous Experiment, Agent Collaboration Optimizer."""

from __future__ import annotations

import pytest

from shieldops.security.security_posture_scorer_engine import (
    ComplianceAlignment,
    PostureDomain,
    PostureMaturity,
    SecurityPostureScorerEngine,
    SecurityPostureScorerRecord,
    SecurityPostureScorerAnalysis,
    SecurityPostureScorerReport,
)
from shieldops.security.threat_simulation_engine import (
    MitreTactic,
    SimulationOutcome,
    SimulationType,
    ThreatSimulationEngine,
    ThreatSimulationRecord,
    ThreatSimulationAnalysis,
    ThreatSimulationReport,
)
from shieldops.analytics.agent_meta_learning_engine import (
    AgentGeneration,
    LearningOutcome,
    MetaStrategy,
    AgentMetaLearningEngine,
    AgentMetaLearningRecord,
    AgentMetaLearningAnalysis,
    AgentMetaLearningReport,
)
from shieldops.analytics.autonomous_experiment_engine import (
    BudgetStatus,
    DecisionOutcome,
    ExperimentPhase,
    AutonomousExperimentEngine,
    AutonomousExperimentRecord,
    AutonomousExperimentAnalysis,
    AutonomousExperimentReport,
)
from shieldops.analytics.agent_collaboration_optimizer_engine import (
    CollaborationMode,
    ConflictType,
    HandoffQuality,
    AgentCollaborationOptimizerEngine,
    AgentCollaborationOptimizerRecord,
    AgentCollaborationOptimizerAnalysis,
    AgentCollaborationOptimizerReport,
)


# ============================================================
# SecurityPostureScorerEngine Tests
# ============================================================


class TestPostureScorerEnums:
    def test_posture_domain_values(self):
        assert PostureDomain.IDENTITY == "identity"
        assert PostureDomain.NETWORK == "network"
        assert PostureDomain.ENDPOINT == "endpoint"
        assert PostureDomain.CLOUD == "cloud"
        assert PostureDomain.DATA == "data"

    def test_posture_maturity_values(self):
        assert PostureMaturity.INITIAL == "initial"
        assert PostureMaturity.OPTIMIZED == "optimized"

    def test_compliance_alignment_values(self):
        assert ComplianceAlignment.ALIGNED == "aligned"
        assert ComplianceAlignment.PARTIAL == "partial"
        assert ComplianceAlignment.GAP == "gap"


class TestPostureScorerModels:
    def test_record_defaults(self):
        r = SecurityPostureScorerRecord()
        assert r.id
        assert r.posture_domain == PostureDomain.IDENTITY
        assert r.control_count == 0

    def test_analysis_defaults(self):
        a = SecurityPostureScorerAnalysis()
        assert a.breached is False

    def test_report_defaults(self):
        r = SecurityPostureScorerReport()
        assert r.by_posture_domain == {}


class TestPostureScorerEngine:
    def setup_method(self):
        self.engine = SecurityPostureScorerEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._threshold == 50.0

    def test_add_record(self):
        r = self.engine.add_record(name="identity-check", score=80.0, service="iam")
        assert r.name == "identity-check"

    def test_get_record(self):
        r = self.engine.add_record(name="test")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self):
        assert self.engine.get_record("xxx") is None

    def test_list_records_by_domain(self):
        self.engine.add_record(name="r1", posture_domain=PostureDomain.NETWORK)
        self.engine.add_record(name="r2", posture_domain=PostureDomain.CLOUD)
        result = self.engine.list_records(posture_domain=PostureDomain.NETWORK)
        assert len(result) == 1

    def test_list_records_by_maturity(self):
        self.engine.add_record(name="r1", posture_maturity=PostureMaturity.OPTIMIZED)
        self.engine.add_record(name="r2", posture_maturity=PostureMaturity.INITIAL)
        result = self.engine.list_records(posture_maturity=PostureMaturity.OPTIMIZED)
        assert len(result) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="a1", analysis_score=75.0)
        assert a.analysis_score == 75.0

    def test_ring_buffer(self):
        engine = SecurityPostureScorerEngine(max_records=2)
        for i in range(4):
            engine.add_record(name=f"r{i}")
        assert len(engine._records) == 2

    def test_compute_domain_scores(self):
        self.engine.add_record(
            name="r1", posture_domain=PostureDomain.IDENTITY, score=80.0,
        )
        self.engine.add_record(
            name="r2", posture_domain=PostureDomain.IDENTITY, score=60.0,
        )
        result = self.engine.compute_domain_scores()
        assert len(result) == 1
        assert result[0]["avg_score"] == 70.0
        assert result[0]["record_count"] == 2

    def test_detect_posture_regression_gaps(self):
        self.engine.add_record(
            name="r1", service="api",
            compliance_alignment=ComplianceAlignment.GAP,
        )
        regressions = self.engine.detect_posture_regression()
        assert len(regressions) == 1
        assert regressions[0]["gap_count"] == 1

    def test_detect_posture_regression_low_maturity(self):
        self.engine.add_record(
            name="r1", service="api",
            posture_maturity=PostureMaturity.INITIAL,
            compliance_alignment=ComplianceAlignment.ALIGNED,
        )
        regressions = self.engine.detect_posture_regression()
        assert len(regressions) == 1
        assert regressions[0]["low_maturity_count"] == 1

    def test_detect_posture_regression_none(self):
        self.engine.add_record(
            name="r1", service="api",
            posture_maturity=PostureMaturity.MANAGED,
            compliance_alignment=ComplianceAlignment.ALIGNED,
        )
        assert len(self.engine.detect_posture_regression()) == 0

    def test_benchmark_against_framework(self):
        self.engine.add_record(
            name="r1", framework="NIST", score=80.0,
            compliance_alignment=ComplianceAlignment.ALIGNED,
        )
        self.engine.add_record(
            name="r2", framework="NIST", score=40.0,
            compliance_alignment=ComplianceAlignment.GAP,
        )
        result = self.engine.benchmark_against_framework()
        assert len(result) == 1
        assert result[0]["framework"] == "NIST"
        assert result[0]["alignment_pct"] == 50.0

    def test_benchmark_no_framework(self):
        self.engine.add_record(name="r1", framework="", score=80.0)
        assert len(self.engine.benchmark_against_framework()) == 0

    def test_process_found(self):
        self.engine.add_record(name="test", score=70.0)
        assert self.engine.process("test")["status"] == "processed"

    def test_process_not_found(self):
        assert self.engine.process("nope")["status"] == "not_found"

    def test_generate_report(self):
        self.engine.add_record(name="r1", score=80.0)
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_generate_report_empty(self):
        report = self.engine.generate_report()
        assert report.avg_score == 0.0

    def test_clear_data(self):
        self.engine.add_record(name="r1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self):
        self.engine.add_record(name="r1", team="sec", service="iam")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1

    def test_identify_gaps(self):
        self.engine.add_record(name="r1", score=20.0)
        assert len(self.engine.identify_gaps()) == 1

    def test_rank_by_score(self):
        self.engine.add_record(name="r1", score=20.0, service="low")
        self.engine.add_record(name="r2", score=90.0, service="high")
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "low"

    def test_analyze_distribution(self):
        self.engine.add_record(name="r1", score=80.0, posture_domain=PostureDomain.DATA)
        dist = self.engine.analyze_distribution()
        assert "data" in dist


# ============================================================
# ThreatSimulationEngine Tests
# ============================================================


class TestThreatSimulationEnums:
    def test_simulation_type_values(self):
        assert SimulationType.TABLETOP == "tabletop"
        assert SimulationType.RED_TEAM == "red_team"
        assert SimulationType.PURPLE_TEAM == "purple_team"
        assert SimulationType.BREACH_SIMULATION == "breach_simulation"

    def test_simulation_outcome_values(self):
        assert SimulationOutcome.DETECTED == "detected"
        assert SimulationOutcome.MISSED == "missed"
        assert SimulationOutcome.BLOCKED == "blocked"

    def test_mitre_tactic_values(self):
        assert MitreTactic.INITIAL_ACCESS == "initial_access"
        assert MitreTactic.LATERAL_MOVEMENT == "lateral_movement"
        assert MitreTactic.IMPACT == "impact"
        assert len(MitreTactic) == 12


class TestThreatSimulationModels:
    def test_record_defaults(self):
        r = ThreatSimulationRecord()
        assert r.technique_count == 0
        assert r.detection_time_seconds == 0.0

    def test_analysis_defaults(self):
        a = ThreatSimulationAnalysis()
        assert a.id

    def test_report_defaults(self):
        r = ThreatSimulationReport()
        assert r.by_mitre_tactic == {}


class TestThreatSimulationEngine:
    def setup_method(self):
        self.engine = ThreatSimulationEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._threshold == 50.0

    def test_add_record(self):
        r = self.engine.add_record(
            name="sim1", simulation_type=SimulationType.RED_TEAM,
            mitre_tactic=MitreTactic.EXECUTION, score=70.0,
        )
        assert r.simulation_type == SimulationType.RED_TEAM

    def test_get_record(self):
        r = self.engine.add_record(name="test")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self):
        assert self.engine.get_record("xxx") is None

    def test_list_records_by_type(self):
        self.engine.add_record(name="r1", simulation_type=SimulationType.RED_TEAM)
        self.engine.add_record(name="r2", simulation_type=SimulationType.TABLETOP)
        result = self.engine.list_records(simulation_type=SimulationType.RED_TEAM)
        assert len(result) == 1

    def test_list_records_by_outcome(self):
        self.engine.add_record(name="r1", simulation_outcome=SimulationOutcome.MISSED)
        self.engine.add_record(name="r2", simulation_outcome=SimulationOutcome.DETECTED)
        result = self.engine.list_records(simulation_outcome=SimulationOutcome.MISSED)
        assert len(result) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="a1")
        assert a.name == "a1"

    def test_ring_buffer(self):
        engine = ThreatSimulationEngine(max_records=2)
        for i in range(4):
            engine.add_record(name=f"r{i}")
        assert len(engine._records) == 2

    def test_identify_detection_gaps(self):
        self.engine.add_record(
            name="r1", mitre_tactic=MitreTactic.EXECUTION,
            simulation_outcome=SimulationOutcome.MISSED,
        )
        self.engine.add_record(
            name="r2", mitre_tactic=MitreTactic.EXECUTION,
            simulation_outcome=SimulationOutcome.DETECTED,
        )
        gaps = self.engine.identify_detection_gaps()
        assert len(gaps) == 1
        assert gaps[0]["tactic"] == "execution"
        assert gaps[0]["missed"] == 1

    def test_identify_detection_gaps_no_gaps(self):
        self.engine.add_record(
            name="r1", simulation_outcome=SimulationOutcome.DETECTED,
        )
        assert len(self.engine.identify_detection_gaps()) == 0

    def test_compute_detection_coverage(self):
        self.engine.add_record(
            name="r1", simulation_type=SimulationType.RED_TEAM,
            simulation_outcome=SimulationOutcome.DETECTED,
            detection_time_seconds=30.0,
        )
        self.engine.add_record(
            name="r2", simulation_type=SimulationType.RED_TEAM,
            simulation_outcome=SimulationOutcome.MISSED,
            detection_time_seconds=0.0,
        )
        result = self.engine.compute_detection_coverage()
        assert len(result) == 1
        assert result[0]["coverage_pct"] == 50.0

    def test_recommend_detection_improvements_missed(self):
        self.engine.add_record(
            name="r1", simulation_outcome=SimulationOutcome.MISSED,
            mitre_tactic=MitreTactic.PERSISTENCE, service="api",
        )
        recs = self.engine.recommend_detection_improvements()
        assert len(recs) == 1
        assert recs[0]["priority"] == "critical"

    def test_recommend_detection_improvements_partial(self):
        self.engine.add_record(
            name="r1", simulation_outcome=SimulationOutcome.PARTIALLY_DETECTED,
            mitre_tactic=MitreTactic.DISCOVERY, service="api",
        )
        recs = self.engine.recommend_detection_improvements()
        assert recs[0]["priority"] == "high"

    def test_recommend_detection_improvements_low_score(self):
        self.engine.add_record(
            name="r1", simulation_outcome=SimulationOutcome.DETECTED,
            score=20.0, service="api",
        )
        recs = self.engine.recommend_detection_improvements()
        assert recs[0]["priority"] == "medium"

    def test_process_found(self):
        self.engine.add_record(name="sim1", score=70.0)
        assert self.engine.process("sim1")["status"] == "processed"

    def test_process_not_found(self):
        assert self.engine.process("nope")["status"] == "not_found"

    def test_generate_report(self):
        self.engine.add_record(name="r1", score=80.0)
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_clear_data(self):
        self.engine.add_record(name="r1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self):
        self.engine.add_record(name="r1", team="red", service="svc1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1

    def test_identify_gaps(self):
        self.engine.add_record(name="r1", score=20.0)
        assert len(self.engine.identify_gaps()) == 1

    def test_rank_by_score(self):
        self.engine.add_record(name="r1", score=20.0, service="low")
        self.engine.add_record(name="r2", score=90.0, service="high")
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "low"

    def test_analyze_distribution(self):
        self.engine.add_record(name="r1", score=80.0, simulation_type=SimulationType.PURPLE_TEAM)
        dist = self.engine.analyze_distribution()
        assert "purple_team" in dist


# ============================================================
# AgentMetaLearningEngine Tests
# ============================================================


class TestMetaLearningEnums:
    def test_meta_strategy_values(self):
        assert MetaStrategy.TRANSFER == "transfer"
        assert MetaStrategy.CURRICULUM == "curriculum"
        assert MetaStrategy.ENSEMBLE == "ensemble"
        assert MetaStrategy.DISTILLATION == "distillation"

    def test_learning_outcome_values(self):
        assert LearningOutcome.IMPROVED == "improved"
        assert LearningOutcome.UNCHANGED == "unchanged"
        assert LearningOutcome.DEGRADED == "degraded"

    def test_agent_generation_values(self):
        assert AgentGeneration.GEN1 == "gen1"
        assert AgentGeneration.EXPERIMENTAL == "experimental"


class TestMetaLearningModels:
    def test_record_defaults(self):
        r = AgentMetaLearningRecord()
        assert r.improvement_pct == 0.0
        assert r.training_cost == 0.0

    def test_analysis_defaults(self):
        a = AgentMetaLearningAnalysis()
        assert a.id

    def test_report_defaults(self):
        r = AgentMetaLearningReport()
        assert r.by_meta_strategy == {}


class TestMetaLearningEngine:
    def setup_method(self):
        self.engine = AgentMetaLearningEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._threshold == 50.0

    def test_add_record(self):
        r = self.engine.add_record(
            name="ml1", meta_strategy=MetaStrategy.TRANSFER,
            improvement_pct=15.0, training_cost=100.0,
        )
        assert r.improvement_pct == 15.0

    def test_get_record(self):
        r = self.engine.add_record(name="test")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self):
        assert self.engine.get_record("xxx") is None

    def test_list_records_by_strategy(self):
        self.engine.add_record(name="r1", meta_strategy=MetaStrategy.ENSEMBLE)
        self.engine.add_record(name="r2", meta_strategy=MetaStrategy.TRANSFER)
        result = self.engine.list_records(meta_strategy=MetaStrategy.ENSEMBLE)
        assert len(result) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="a1")
        assert a.name == "a1"

    def test_ring_buffer(self):
        engine = AgentMetaLearningEngine(max_records=2)
        for i in range(4):
            engine.add_record(name=f"r{i}")
        assert len(engine._records) == 2

    def test_identify_best_learning_strategies(self):
        self.engine.add_record(
            name="r1", meta_strategy=MetaStrategy.TRANSFER,
            learning_outcome=LearningOutcome.IMPROVED,
            improvement_pct=20.0, training_cost=50.0,
        )
        self.engine.add_record(
            name="r2", meta_strategy=MetaStrategy.TRANSFER,
            learning_outcome=LearningOutcome.DEGRADED,
            improvement_pct=-5.0, training_cost=50.0,
        )
        result = self.engine.identify_best_learning_strategies()
        assert len(result) == 1
        assert result[0]["strategy"] == "transfer"
        assert result[0]["success_rate"] == 50.0

    def test_cross_pollinate_agent_knowledge(self):
        self.engine.add_record(
            name="r1", agent_generation=AgentGeneration.GEN1,
            meta_strategy=MetaStrategy.CURRICULUM, improvement_pct=15.0,
        )
        self.engine.add_record(
            name="r2", agent_generation=AgentGeneration.GEN2,
            meta_strategy=MetaStrategy.TRANSFER, improvement_pct=10.0,
        )
        result = self.engine.cross_pollinate_agent_knowledge()
        assert len(result) >= 1

    def test_cross_pollinate_no_opportunities(self):
        self.engine.add_record(
            name="r1", agent_generation=AgentGeneration.GEN1,
            meta_strategy=MetaStrategy.TRANSFER, improvement_pct=10.0,
        )
        self.engine.add_record(
            name="r2", agent_generation=AgentGeneration.GEN2,
            meta_strategy=MetaStrategy.TRANSFER, improvement_pct=10.0,
        )
        result = self.engine.cross_pollinate_agent_knowledge()
        assert len(result) == 0

    def test_evaluate_meta_learning_roi(self):
        self.engine.add_record(
            name="r1", meta_strategy=MetaStrategy.ENSEMBLE,
            improvement_pct=20.0, training_cost=100.0,
            learning_outcome=LearningOutcome.IMPROVED,
        )
        result = self.engine.evaluate_meta_learning_roi()
        assert len(result) == 1
        assert result[0]["roi"] == 0.2

    def test_evaluate_roi_zero_cost(self):
        self.engine.add_record(
            name="r1", meta_strategy=MetaStrategy.DISTILLATION,
            improvement_pct=10.0, training_cost=0.0,
        )
        result = self.engine.evaluate_meta_learning_roi()
        assert result[0]["roi"] == 0.0

    def test_process_found(self):
        self.engine.add_record(name="test", score=70.0)
        assert self.engine.process("test")["status"] == "processed"

    def test_process_not_found(self):
        assert self.engine.process("nope")["status"] == "not_found"

    def test_generate_report(self):
        self.engine.add_record(name="r1", score=80.0)
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_generate_report_empty(self):
        report = self.engine.generate_report()
        assert report.avg_score == 0.0

    def test_clear_data(self):
        self.engine.add_record(name="r1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self):
        self.engine.add_record(name="r1", team="ml", service="agent1")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1

    def test_identify_gaps(self):
        self.engine.add_record(name="r1", score=20.0)
        assert len(self.engine.identify_gaps()) == 1

    def test_rank_by_score(self):
        self.engine.add_record(name="r1", score=20.0, service="low")
        self.engine.add_record(name="r2", score=90.0, service="high")
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "low"

    def test_analyze_distribution(self):
        self.engine.add_record(name="r1", score=80.0, meta_strategy=MetaStrategy.CURRICULUM)
        dist = self.engine.analyze_distribution()
        assert "curriculum" in dist


# ============================================================
# AutonomousExperimentEngine Tests
# ============================================================


class TestAutonomousExperimentEnums:
    def test_experiment_phase_values(self):
        assert ExperimentPhase.HYPOTHESIS == "hypothesis"
        assert ExperimentPhase.DESIGN == "design"
        assert ExperimentPhase.EXECUTE == "execute"
        assert ExperimentPhase.ANALYZE == "analyze"
        assert ExperimentPhase.DECIDE == "decide"

    def test_budget_status_values(self):
        assert BudgetStatus.UNDER_BUDGET == "under_budget"
        assert BudgetStatus.EXHAUSTED == "exhausted"

    def test_decision_outcome_values(self):
        assert DecisionOutcome.ACCEPT == "accept"
        assert DecisionOutcome.PIVOT == "pivot"


class TestAutonomousExperimentModels:
    def test_record_defaults(self):
        r = AutonomousExperimentRecord()
        assert r.budget_spent == 0.0
        assert r.budget_total == 0.0

    def test_analysis_defaults(self):
        a = AutonomousExperimentAnalysis()
        assert a.id

    def test_report_defaults(self):
        r = AutonomousExperimentReport()
        assert r.by_experiment_phase == {}


class TestAutonomousExperimentEngine:
    def setup_method(self):
        self.engine = AutonomousExperimentEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._threshold == 50.0

    def test_add_record(self):
        r = self.engine.add_record(
            name="exp1", experiment_phase=ExperimentPhase.EXECUTE,
            budget_spent=500.0, budget_total=1000.0,
        )
        assert r.budget_spent == 500.0

    def test_get_record(self):
        r = self.engine.add_record(name="test")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self):
        assert self.engine.get_record("xxx") is None

    def test_list_records_by_phase(self):
        self.engine.add_record(name="r1", experiment_phase=ExperimentPhase.EXECUTE)
        self.engine.add_record(name="r2", experiment_phase=ExperimentPhase.DECIDE)
        result = self.engine.list_records(experiment_phase=ExperimentPhase.EXECUTE)
        assert len(result) == 1

    def test_list_records_by_budget(self):
        self.engine.add_record(name="r1", budget_status=BudgetStatus.OVER_BUDGET)
        self.engine.add_record(name="r2", budget_status=BudgetStatus.UNDER_BUDGET)
        result = self.engine.list_records(budget_status=BudgetStatus.OVER_BUDGET)
        assert len(result) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="a1")
        assert a.name == "a1"

    def test_ring_buffer(self):
        engine = AutonomousExperimentEngine(max_records=2)
        for i in range(4):
            engine.add_record(name=f"r{i}")
        assert len(engine._records) == 2

    def test_generate_experiment_hypotheses_rejected(self):
        self.engine.add_record(
            name="r1", service="api", decision_outcome=DecisionOutcome.REJECT,
        )
        self.engine.add_record(
            name="r2", service="api", decision_outcome=DecisionOutcome.REJECT,
        )
        self.engine.add_record(
            name="r3", service="api", decision_outcome=DecisionOutcome.ACCEPT,
        )
        hypotheses = self.engine.generate_experiment_hypotheses()
        assert len(hypotheses) >= 1
        assert any("fundamentally different" in h["hypothesis"] for h in hypotheses)

    def test_generate_experiment_hypotheses_pivoted(self):
        self.engine.add_record(
            name="r1", service="api", decision_outcome=DecisionOutcome.PIVOT,
        )
        hypotheses = self.engine.generate_experiment_hypotheses()
        assert any("scoping" in h["hypothesis"] for h in hypotheses)

    def test_enforce_budget_constraints_exhausted(self):
        self.engine.add_record(
            name="exp1", budget_status=BudgetStatus.EXHAUSTED,
            budget_spent=1000.0, budget_total=1000.0, service="api",
        )
        violations = self.engine.enforce_budget_constraints()
        assert len(violations) == 1
        assert violations[0]["action"] == "halt"
        assert violations[0]["severity"] == "critical"

    def test_enforce_budget_constraints_over_budget(self):
        self.engine.add_record(
            name="exp1", budget_status=BudgetStatus.OVER_BUDGET,
            budget_spent=1200.0, budget_total=1000.0, service="api",
        )
        violations = self.engine.enforce_budget_constraints()
        assert violations[0]["action"] == "review"

    def test_enforce_budget_constraints_at_limit(self):
        self.engine.add_record(
            name="exp1", budget_status=BudgetStatus.AT_LIMIT,
            budget_spent=990.0, budget_total=1000.0, service="api",
        )
        violations = self.engine.enforce_budget_constraints()
        assert violations[0]["action"] == "monitor"

    def test_enforce_budget_constraints_ok(self):
        self.engine.add_record(
            name="exp1", budget_status=BudgetStatus.UNDER_BUDGET,
        )
        assert len(self.engine.enforce_budget_constraints()) == 0

    def test_compute_experiment_roi(self):
        self.engine.add_record(
            name="r1", service="api", score=80.0, budget_spent=100.0,
            decision_outcome=DecisionOutcome.ACCEPT,
        )
        result = self.engine.compute_experiment_roi()
        assert len(result) == 1
        assert result[0]["roi"] == 0.8

    def test_compute_experiment_roi_zero_spend(self):
        self.engine.add_record(
            name="r1", service="api", score=80.0, budget_spent=0.0,
        )
        result = self.engine.compute_experiment_roi()
        assert result[0]["roi"] == 0.0

    def test_process_found(self):
        self.engine.add_record(name="test", score=70.0)
        assert self.engine.process("test")["status"] == "processed"

    def test_process_not_found(self):
        assert self.engine.process("nope")["status"] == "not_found"

    def test_generate_report(self):
        self.engine.add_record(name="r1", score=80.0)
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_clear_data(self):
        self.engine.add_record(name="r1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self):
        self.engine.add_record(name="r1", team="research", service="api")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1

    def test_identify_gaps(self):
        self.engine.add_record(name="r1", score=20.0)
        assert len(self.engine.identify_gaps()) == 1

    def test_rank_by_score(self):
        self.engine.add_record(name="r1", score=20.0, service="low")
        self.engine.add_record(name="r2", score=90.0, service="high")
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "low"

    def test_analyze_distribution(self):
        self.engine.add_record(
            name="r1", score=80.0, experiment_phase=ExperimentPhase.ANALYZE,
        )
        dist = self.engine.analyze_distribution()
        assert "analyze" in dist


# ============================================================
# AgentCollaborationOptimizerEngine Tests
# ============================================================


class TestCollaborationOptimizerEnums:
    def test_collaboration_mode_values(self):
        assert CollaborationMode.SEQUENTIAL == "sequential"
        assert CollaborationMode.PARALLEL == "parallel"
        assert CollaborationMode.CONSENSUS == "consensus"
        assert CollaborationMode.HIERARCHICAL == "hierarchical"

    def test_handoff_quality_values(self):
        assert HandoffQuality.CLEAN == "clean"
        assert HandoffQuality.PARTIAL == "partial"
        assert HandoffQuality.FAILED == "failed"
        assert HandoffQuality.REDUNDANT == "redundant"

    def test_conflict_type_values(self):
        assert ConflictType.RESOURCE == "resource"
        assert ConflictType.PRIORITY == "priority"
        assert ConflictType.DATA == "data"
        assert ConflictType.DECISION == "decision"


class TestCollaborationOptimizerModels:
    def test_record_defaults(self):
        r = AgentCollaborationOptimizerRecord()
        assert r.agent_count == 0
        assert r.latency_ms == 0.0

    def test_analysis_defaults(self):
        a = AgentCollaborationOptimizerAnalysis()
        assert a.id

    def test_report_defaults(self):
        r = AgentCollaborationOptimizerReport()
        assert r.by_collaboration_mode == {}


class TestCollaborationOptimizerEngine:
    def setup_method(self):
        self.engine = AgentCollaborationOptimizerEngine(max_records=100, threshold=50.0)

    def test_init(self):
        assert self.engine._threshold == 50.0

    def test_add_record(self):
        r = self.engine.add_record(
            name="collab1", collaboration_mode=CollaborationMode.PARALLEL,
            agent_count=3, latency_ms=150.0,
        )
        assert r.agent_count == 3

    def test_get_record(self):
        r = self.engine.add_record(name="test")
        assert self.engine.get_record(r.id) is not None

    def test_get_record_not_found(self):
        assert self.engine.get_record("xxx") is None

    def test_list_records_by_mode(self):
        self.engine.add_record(name="r1", collaboration_mode=CollaborationMode.PARALLEL)
        self.engine.add_record(name="r2", collaboration_mode=CollaborationMode.SEQUENTIAL)
        result = self.engine.list_records(collaboration_mode=CollaborationMode.PARALLEL)
        assert len(result) == 1

    def test_list_records_by_quality(self):
        self.engine.add_record(name="r1", handoff_quality=HandoffQuality.FAILED)
        self.engine.add_record(name="r2", handoff_quality=HandoffQuality.CLEAN)
        result = self.engine.list_records(handoff_quality=HandoffQuality.FAILED)
        assert len(result) == 1

    def test_add_analysis(self):
        a = self.engine.add_analysis(name="a1")
        assert a.name == "a1"

    def test_ring_buffer(self):
        engine = AgentCollaborationOptimizerEngine(max_records=2)
        for i in range(4):
            engine.add_record(name=f"r{i}")
        assert len(engine._records) == 2

    def test_detect_collaboration_bottlenecks(self):
        self.engine.add_record(
            name="r1", collaboration_mode=CollaborationMode.SEQUENTIAL,
            handoff_quality=HandoffQuality.FAILED, latency_ms=500.0,
        )
        self.engine.add_record(
            name="r2", collaboration_mode=CollaborationMode.SEQUENTIAL,
            handoff_quality=HandoffQuality.CLEAN, latency_ms=100.0,
        )
        bottlenecks = self.engine.detect_collaboration_bottlenecks()
        assert len(bottlenecks) == 1
        assert bottlenecks[0]["failed_handoffs"] == 1

    def test_detect_collaboration_bottlenecks_empty(self):
        self.engine.add_record(
            name="r1", handoff_quality=HandoffQuality.CLEAN,
        )
        assert len(self.engine.detect_collaboration_bottlenecks()) == 0

    def test_optimize_agent_handoffs_failed(self):
        self.engine.add_record(
            name="r1", service="api", handoff_quality=HandoffQuality.FAILED,
        )
        opts = self.engine.optimize_agent_handoffs()
        assert any(o["priority"] == "critical" for o in opts)

    def test_optimize_agent_handoffs_redundant(self):
        self.engine.add_record(
            name="r1", service="api", handoff_quality=HandoffQuality.REDUNDANT,
        )
        opts = self.engine.optimize_agent_handoffs()
        assert any(o["issue"] == "redundant_handoffs" for o in opts)

    def test_optimize_agent_handoffs_all_clean(self):
        self.engine.add_record(
            name="r1", service="api", handoff_quality=HandoffQuality.CLEAN,
        )
        opts = self.engine.optimize_agent_handoffs()
        assert any(o["issue"] == "none" for o in opts)

    def test_resolve_agent_conflicts(self):
        self.engine.add_record(
            name="r1", handoff_quality=HandoffQuality.FAILED,
            conflict_type=ConflictType.RESOURCE, service="api", score=30.0,
        )
        self.engine.add_record(
            name="r2", handoff_quality=HandoffQuality.FAILED,
            conflict_type=ConflictType.RESOURCE, service="db", score=20.0,
        )
        resolutions = self.engine.resolve_agent_conflicts()
        assert len(resolutions) == 1
        assert resolutions[0]["conflict_type"] == "resource"
        assert "locking" in resolutions[0]["resolution"]

    def test_resolve_agent_conflicts_data(self):
        self.engine.add_record(
            name="r1", handoff_quality=HandoffQuality.PARTIAL,
            conflict_type=ConflictType.DATA, service="api",
        )
        resolutions = self.engine.resolve_agent_conflicts()
        assert any("validation" in r["resolution"] for r in resolutions)

    def test_resolve_agent_conflicts_no_conflicts(self):
        self.engine.add_record(
            name="r1", handoff_quality=HandoffQuality.CLEAN,
        )
        assert len(self.engine.resolve_agent_conflicts()) == 0

    def test_process_found(self):
        self.engine.add_record(name="test", score=70.0)
        assert self.engine.process("test")["status"] == "processed"

    def test_process_not_found(self):
        assert self.engine.process("nope")["status"] == "not_found"

    def test_generate_report(self):
        self.engine.add_record(name="r1", score=80.0)
        report = self.engine.generate_report()
        assert report.total_records == 1

    def test_generate_report_empty(self):
        report = self.engine.generate_report()
        assert report.avg_score == 0.0

    def test_clear_data(self):
        self.engine.add_record(name="r1")
        self.engine.clear_data()
        assert len(self.engine._records) == 0

    def test_get_stats(self):
        self.engine.add_record(name="r1", team="platform", service="orchestrator")
        stats = self.engine.get_stats()
        assert stats["total_records"] == 1

    def test_identify_gaps(self):
        self.engine.add_record(name="r1", score=20.0)
        assert len(self.engine.identify_gaps()) == 1

    def test_rank_by_score(self):
        self.engine.add_record(name="r1", score=20.0, service="low")
        self.engine.add_record(name="r2", score=90.0, service="high")
        ranked = self.engine.rank_by_score()
        assert ranked[0]["service"] == "low"

    def test_analyze_distribution(self):
        self.engine.add_record(
            name="r1", score=80.0,
            collaboration_mode=CollaborationMode.CONSENSUS,
        )
        dist = self.engine.analyze_distribution()
        assert "consensus" in dist

    def test_list_records_by_team(self):
        self.engine.add_record(name="r1", team="alpha")
        self.engine.add_record(name="r2", team="beta")
        result = self.engine.list_records(team="alpha")
        assert len(result) == 1

    def test_list_records_limit(self):
        for i in range(10):
            self.engine.add_record(name=f"r{i}")
        assert len(self.engine.list_records(limit=3)) == 3
