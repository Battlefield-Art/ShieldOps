"""Tests for multi-agent learning engines — self-healing analytics, swarm intelligence,
learning feedback loop, agent knowledge distillation."""

from __future__ import annotations

from shieldops.analytics.agent_knowledge_distillation_engine import (
    AgentKnowledgeDistillationEngine,
    DistillationAnalysis,
    DistillationMethod,
    DistillationRecord,
    DistillationReport,
    KnowledgeType,
    TransferOutcome,
)
from shieldops.analytics.learning_feedback_loop_engine import (
    ConvergenceStatus,
    FeedbackType,
    LearningFeedbackAnalysis,
    LearningFeedbackLoopEngine,
    LearningFeedbackRecord,
    LearningFeedbackReport,
    LearningPhase,
)
from shieldops.analytics.self_healing_analytics_engine import (
    HealingAction,
    HealingOutcome,
    HealingTrigger,
    SelfHealingAnalysis,
    SelfHealingAnalyticsEngine,
    SelfHealingRecord,
    SelfHealingReport,
)
from shieldops.analytics.swarm_intelligence_engine import (
    CoordinationPattern,
    SwarmHealth,
    SwarmIntelligenceAnalysis,
    SwarmIntelligenceEngine,
    SwarmIntelligenceRecord,
    SwarmIntelligenceReport,
    SwarmRole,
)

# ===========================================================================
# 1. SelfHealingAnalyticsEngine
# ===========================================================================


class TestSelfHealingEnums:
    def test_healing_action_values(self):
        assert HealingAction.RESTART == "restart"
        assert HealingAction.SCALE == "scale"
        assert HealingAction.FAILOVER == "failover"
        assert HealingAction.ROLLBACK == "rollback"

    def test_healing_outcome_values(self):
        assert HealingOutcome.RESOLVED == "resolved"
        assert HealingOutcome.PARTIAL == "partial"
        assert HealingOutcome.FAILED == "failed"
        assert HealingOutcome.ESCALATED == "escalated"

    def test_healing_trigger_values(self):
        assert HealingTrigger.ALERT == "alert"
        assert HealingTrigger.THRESHOLD == "threshold"
        assert HealingTrigger.PREDICTION == "prediction"
        assert HealingTrigger.MANUAL == "manual"


class TestSelfHealingModels:
    def test_record_defaults(self):
        r = SelfHealingRecord()
        assert r.id
        assert r.service_name == ""
        assert r.incident_id == ""
        assert r.healing_action == HealingAction.RESTART
        assert r.healing_outcome == HealingOutcome.FAILED
        assert r.healing_trigger == HealingTrigger.ALERT
        assert r.execution_time_seconds == 0.0
        assert r.downtime_seconds == 0.0
        assert r.success_rate == 0.0
        assert r.retry_count == 0
        assert r.confidence_score == 0.0
        assert r.description == ""
        assert r.created_at > 0

    def test_analysis_defaults(self):
        a = SelfHealingAnalysis()
        assert a.id
        assert a.service_name == ""
        assert a.healing_action == HealingAction.RESTART
        assert a.healing_outcome == HealingOutcome.FAILED
        assert a.effectiveness_score == 0.0
        assert a.created_at > 0

    def test_report_defaults(self):
        r = SelfHealingReport()
        assert r.id
        assert r.total_records == 0
        assert r.total_analyses == 0
        assert r.avg_success_rate == 0.0
        assert r.by_healing_action == {}
        assert r.by_healing_outcome == {}
        assert r.by_healing_trigger == {}
        assert r.failing_services == []
        assert r.recommendations == []
        assert r.generated_at > 0


class TestSelfHealingAddRecord:
    def test_basic(self):
        eng = SelfHealingAnalyticsEngine()
        r = eng.add_record(
            service_name="api-gateway",
            incident_id="inc-001",
            healing_action=HealingAction.FAILOVER,
            healing_outcome=HealingOutcome.RESOLVED,
            healing_trigger=HealingTrigger.PREDICTION,
            execution_time_seconds=12.5,
            success_rate=0.95,
            confidence_score=0.9,
        )
        assert r.service_name == "api-gateway"
        assert r.healing_action == HealingAction.FAILOVER
        assert r.healing_outcome == HealingOutcome.RESOLVED
        assert r.success_rate == 0.95

    def test_defaults(self):
        eng = SelfHealingAnalyticsEngine()
        r = eng.add_record()
        assert r.service_name == ""
        assert r.healing_action == HealingAction.RESTART

    def test_ring_buffer_eviction(self):
        eng = SelfHealingAnalyticsEngine(max_records=3)
        ids = []
        for i in range(5):
            rec = eng.add_record(service_name=f"svc-{i}")
            ids.append(rec.id)
        assert len(eng._records) == 3
        remaining_ids = [r.id for r in eng._records]
        assert ids[0] not in remaining_ids
        assert ids[1] not in remaining_ids
        assert ids[4] in remaining_ids


class TestSelfHealingProcess:
    def test_process_found_resolved(self):
        eng = SelfHealingAnalyticsEngine()
        r = eng.add_record(
            service_name="auth",
            healing_outcome=HealingOutcome.RESOLVED,
            success_rate=0.8,
            confidence_score=0.9,
        )
        result = eng.process(r.id)
        assert isinstance(result, SelfHealingAnalysis)
        assert result.service_name == "auth"
        assert result.effectiveness_score == round(0.8 * 0.9, 4)

    def test_process_found_partial(self):
        eng = SelfHealingAnalyticsEngine()
        r = eng.add_record(
            healing_outcome=HealingOutcome.PARTIAL,
            success_rate=0.6,
        )
        result = eng.process(r.id)
        assert isinstance(result, SelfHealingAnalysis)
        assert result.effectiveness_score == round(0.6 * 0.5, 4)

    def test_process_found_escalated(self):
        eng = SelfHealingAnalyticsEngine()
        r = eng.add_record(
            healing_outcome=HealingOutcome.ESCALATED,
            success_rate=0.6,
        )
        result = eng.process(r.id)
        assert isinstance(result, SelfHealingAnalysis)
        assert result.effectiveness_score == round(0.6 * 0.3, 4)

    def test_process_found_failed(self):
        eng = SelfHealingAnalyticsEngine()
        r = eng.add_record(healing_outcome=HealingOutcome.FAILED, success_rate=0.9)
        result = eng.process(r.id)
        assert isinstance(result, SelfHealingAnalysis)
        assert result.effectiveness_score == 0.0

    def test_process_not_found(self):
        eng = SelfHealingAnalyticsEngine()
        result = eng.process("nonexistent")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"


class TestSelfHealingReport:
    def test_generate_report_populated(self):
        eng = SelfHealingAnalyticsEngine()
        eng.add_record(
            service_name="api",
            healing_action=HealingAction.RESTART,
            healing_outcome=HealingOutcome.RESOLVED,
            healing_trigger=HealingTrigger.ALERT,
            success_rate=0.9,
        )
        eng.add_record(
            service_name="db",
            healing_action=HealingAction.FAILOVER,
            healing_outcome=HealingOutcome.FAILED,
            healing_trigger=HealingTrigger.THRESHOLD,
            success_rate=0.2,
        )
        report = eng.generate_report()
        assert isinstance(report, SelfHealingReport)
        assert report.total_records == 2
        assert report.by_healing_action["restart"] == 1
        assert report.by_healing_action["failover"] == 1
        assert report.by_healing_outcome["resolved"] == 1
        assert report.by_healing_outcome["failed"] == 1
        assert "db" in report.failing_services

    def test_generate_report_empty(self):
        eng = SelfHealingAnalyticsEngine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert report.avg_success_rate == 0.0

    def test_generate_report_low_success_rate(self):
        eng = SelfHealingAnalyticsEngine()
        eng.add_record(success_rate=0.1)
        eng.add_record(success_rate=0.2)
        report = eng.generate_report()
        assert report.avg_success_rate < 0.5
        assert any("below 50%" in r for r in report.recommendations)

    def test_generate_report_healthy(self):
        eng = SelfHealingAnalyticsEngine()
        eng.add_record(
            healing_outcome=HealingOutcome.RESOLVED,
            success_rate=0.95,
        )
        report = eng.generate_report()
        assert any("normal parameters" in r for r in report.recommendations)


class TestSelfHealingStats:
    def test_get_stats_empty(self):
        eng = SelfHealingAnalyticsEngine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0
        assert stats["total_analyses"] == 0
        assert stats["healing_action_distribution"] == {}

    def test_get_stats_populated(self):
        eng = SelfHealingAnalyticsEngine()
        eng.add_record(healing_action=HealingAction.RESTART)
        eng.add_record(healing_action=HealingAction.RESTART)
        eng.add_record(healing_action=HealingAction.SCALE)
        stats = eng.get_stats()
        assert stats["total_records"] == 3
        assert stats["healing_action_distribution"]["restart"] == 2
        assert stats["healing_action_distribution"]["scale"] == 1

    def test_clear_data(self):
        eng = SelfHealingAnalyticsEngine()
        r = eng.add_record(service_name="api")
        eng.process(r.id)
        result = eng.clear_data()
        assert result == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


class TestSelfHealingDomainMethods:
    def test_evaluate_healing_effectiveness(self):
        eng = SelfHealingAnalyticsEngine()
        eng.add_record(
            healing_action=HealingAction.RESTART,
            healing_outcome=HealingOutcome.RESOLVED,
            execution_time_seconds=5.0,
            downtime_seconds=10.0,
        )
        eng.add_record(
            healing_action=HealingAction.RESTART,
            healing_outcome=HealingOutcome.FAILED,
            execution_time_seconds=15.0,
            downtime_seconds=30.0,
        )
        results = eng.evaluate_healing_effectiveness()
        assert len(results) == 1
        assert results[0]["healing_action"] == "restart"
        assert results[0]["success_rate"] == 0.5
        assert results[0]["total_executions"] == 2

    def test_evaluate_healing_effectiveness_empty(self):
        eng = SelfHealingAnalyticsEngine()
        assert eng.evaluate_healing_effectiveness() == []

    def test_evaluate_healing_effectiveness_ratings(self):
        eng = SelfHealingAnalyticsEngine()
        # 10 resolved out of 10 = excellent
        for _ in range(10):
            eng.add_record(
                healing_action=HealingAction.SCALE,
                healing_outcome=HealingOutcome.RESOLVED,
            )
        results = eng.evaluate_healing_effectiveness()
        assert results[0]["rating"] == "excellent"

    def test_identify_healing_patterns(self):
        eng = SelfHealingAnalyticsEngine()
        eng.add_record(
            healing_trigger=HealingTrigger.ALERT,
            healing_action=HealingAction.RESTART,
            healing_outcome=HealingOutcome.RESOLVED,
        )
        eng.add_record(
            healing_trigger=HealingTrigger.ALERT,
            healing_action=HealingAction.RESTART,
            healing_outcome=HealingOutcome.RESOLVED,
        )
        eng.add_record(
            healing_trigger=HealingTrigger.ALERT,
            healing_action=HealingAction.SCALE,
            healing_outcome=HealingOutcome.FAILED,
        )
        results = eng.identify_healing_patterns()
        assert len(results) == 1
        assert results[0]["trigger"] == "alert"
        assert results[0]["dominant_action"] == "restart"
        assert results[0]["total_events"] == 3

    def test_identify_healing_patterns_empty(self):
        eng = SelfHealingAnalyticsEngine()
        assert eng.identify_healing_patterns() == []

    def test_recommend_healing_improvements(self):
        eng = SelfHealingAnalyticsEngine()
        eng.add_record(
            service_name="api",
            healing_outcome=HealingOutcome.FAILED,
            retry_count=5,
            confidence_score=0.3,
        )
        eng.add_record(
            service_name="api",
            healing_outcome=HealingOutcome.FAILED,
            retry_count=4,
            confidence_score=0.2,
        )
        results = eng.recommend_healing_improvements()
        assert len(results) == 1
        assert results[0]["service_name"] == "api"
        assert results[0]["failure_rate"] == 1.0
        assert any("Review" in imp for imp in results[0]["improvements"])
        assert any("Reduce retry" in imp for imp in results[0]["improvements"])
        assert any("Improve confidence" in imp for imp in results[0]["improvements"])

    def test_recommend_healing_improvements_empty(self):
        eng = SelfHealingAnalyticsEngine()
        assert eng.recommend_healing_improvements() == []

    def test_recommend_healing_improvements_healthy(self):
        eng = SelfHealingAnalyticsEngine()
        eng.add_record(
            service_name="api",
            healing_outcome=HealingOutcome.RESOLVED,
            retry_count=0,
            confidence_score=0.9,
        )
        results = eng.recommend_healing_improvements()
        assert len(results) == 1
        assert "performing well" in results[0]["improvements"][0]


# ===========================================================================
# 2. SwarmIntelligenceEngine
# ===========================================================================


class TestSwarmEnums:
    def test_swarm_role_values(self):
        assert SwarmRole.LEADER == "leader"
        assert SwarmRole.WORKER == "worker"
        assert SwarmRole.OBSERVER == "observer"
        assert SwarmRole.COORDINATOR == "coordinator"

    def test_coordination_pattern_values(self):
        assert CoordinationPattern.CONSENSUS == "consensus"
        assert CoordinationPattern.AUCTION == "auction"
        assert CoordinationPattern.VOTING == "voting"
        assert CoordinationPattern.DELEGATION == "delegation"

    def test_swarm_health_values(self):
        assert SwarmHealth.OPTIMAL == "optimal"
        assert SwarmHealth.DEGRADED == "degraded"
        assert SwarmHealth.FRAGMENTED == "fragmented"
        assert SwarmHealth.FAILED == "failed"


class TestSwarmModels:
    def test_record_defaults(self):
        r = SwarmIntelligenceRecord()
        assert r.id
        assert r.agent_id == ""
        assert r.swarm_id == ""
        assert r.swarm_role == SwarmRole.WORKER
        assert r.coordination_pattern == CoordinationPattern.CONSENSUS
        assert r.swarm_health == SwarmHealth.OPTIMAL
        assert r.task_completion_rate == 0.0
        assert r.response_time_seconds == 0.0
        assert r.messages_sent == 0
        assert r.tasks_assigned == 0
        assert r.tasks_completed == 0
        assert r.created_at > 0

    def test_analysis_defaults(self):
        a = SwarmIntelligenceAnalysis()
        assert a.id
        assert a.swarm_id == ""
        assert a.coordination_score == 0.0
        assert a.created_at > 0

    def test_report_defaults(self):
        r = SwarmIntelligenceReport()
        assert r.id
        assert r.total_records == 0
        assert r.total_analyses == 0
        assert r.avg_completion_rate == 0.0
        assert r.by_swarm_role == {}
        assert r.by_coordination_pattern == {}
        assert r.by_swarm_health == {}
        assert r.unhealthy_swarms == []
        assert r.recommendations == []
        assert r.generated_at > 0


class TestSwarmAddRecord:
    def test_basic(self):
        eng = SwarmIntelligenceEngine()
        r = eng.add_record(
            agent_id="agent-1",
            swarm_id="swarm-1",
            swarm_role=SwarmRole.LEADER,
            coordination_pattern=CoordinationPattern.AUCTION,
            swarm_health=SwarmHealth.OPTIMAL,
            task_completion_rate=0.85,
            response_time_seconds=2.5,
            messages_sent=50,
            tasks_assigned=10,
            tasks_completed=8,
        )
        assert r.agent_id == "agent-1"
        assert r.swarm_id == "swarm-1"
        assert r.swarm_role == SwarmRole.LEADER
        assert r.task_completion_rate == 0.85

    def test_defaults(self):
        eng = SwarmIntelligenceEngine()
        r = eng.add_record()
        assert r.agent_id == ""
        assert r.swarm_role == SwarmRole.WORKER

    def test_ring_buffer_eviction(self):
        eng = SwarmIntelligenceEngine(max_records=3)
        ids = []
        for i in range(5):
            rec = eng.add_record(agent_id=f"a-{i}")
            ids.append(rec.id)
        assert len(eng._records) == 3
        remaining = [r.id for r in eng._records]
        assert ids[0] not in remaining
        assert ids[4] in remaining


class TestSwarmProcess:
    def test_process_found_optimal(self):
        eng = SwarmIntelligenceEngine()
        r = eng.add_record(
            swarm_id="swarm-1",
            swarm_health=SwarmHealth.OPTIMAL,
            task_completion_rate=0.9,
        )
        result = eng.process(r.id)
        assert isinstance(result, SwarmIntelligenceAnalysis)
        assert result.swarm_id == "swarm-1"
        # 0.9*0.7 + 1.0*0.3 = 0.93
        assert result.coordination_score == round(0.9 * 0.7 + 1.0 * 0.3, 4)

    def test_process_found_degraded(self):
        eng = SwarmIntelligenceEngine()
        r = eng.add_record(
            swarm_health=SwarmHealth.DEGRADED,
            task_completion_rate=0.5,
        )
        result = eng.process(r.id)
        assert isinstance(result, SwarmIntelligenceAnalysis)
        assert result.coordination_score == round(0.5 * 0.7 + 0.6 * 0.3, 4)

    def test_process_found_failed(self):
        eng = SwarmIntelligenceEngine()
        r = eng.add_record(
            swarm_health=SwarmHealth.FAILED,
            task_completion_rate=0.0,
        )
        result = eng.process(r.id)
        assert isinstance(result, SwarmIntelligenceAnalysis)
        assert result.coordination_score == 0.0

    def test_process_not_found(self):
        eng = SwarmIntelligenceEngine()
        result = eng.process("nonexistent")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"


class TestSwarmReport:
    def test_generate_report_populated(self):
        eng = SwarmIntelligenceEngine()
        eng.add_record(
            swarm_id="swarm-1",
            swarm_role=SwarmRole.LEADER,
            coordination_pattern=CoordinationPattern.CONSENSUS,
            swarm_health=SwarmHealth.OPTIMAL,
            task_completion_rate=0.9,
        )
        eng.add_record(
            swarm_id="swarm-2",
            swarm_role=SwarmRole.WORKER,
            coordination_pattern=CoordinationPattern.AUCTION,
            swarm_health=SwarmHealth.FRAGMENTED,
            task_completion_rate=0.3,
        )
        report = eng.generate_report()
        assert isinstance(report, SwarmIntelligenceReport)
        assert report.total_records == 2
        assert report.by_swarm_role["leader"] == 1
        assert report.by_swarm_role["worker"] == 1
        assert report.by_coordination_pattern["consensus"] == 1
        assert "swarm-2" in report.unhealthy_swarms

    def test_generate_report_empty(self):
        eng = SwarmIntelligenceEngine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert report.avg_completion_rate == 0.0

    def test_generate_report_healthy(self):
        eng = SwarmIntelligenceEngine()
        eng.add_record(
            swarm_health=SwarmHealth.OPTIMAL,
            task_completion_rate=0.95,
        )
        report = eng.generate_report()
        assert any("normal parameters" in r for r in report.recommendations)

    def test_generate_report_low_completion(self):
        eng = SwarmIntelligenceEngine()
        eng.add_record(task_completion_rate=0.1)
        eng.add_record(task_completion_rate=0.2)
        report = eng.generate_report()
        assert any("below 50%" in r for r in report.recommendations)


class TestSwarmStats:
    def test_get_stats_empty(self):
        eng = SwarmIntelligenceEngine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0
        assert stats["total_analyses"] == 0
        assert stats["swarm_role_distribution"] == {}

    def test_get_stats_populated(self):
        eng = SwarmIntelligenceEngine()
        eng.add_record(swarm_role=SwarmRole.LEADER)
        eng.add_record(swarm_role=SwarmRole.WORKER)
        eng.add_record(swarm_role=SwarmRole.WORKER)
        stats = eng.get_stats()
        assert stats["total_records"] == 3
        assert stats["swarm_role_distribution"]["leader"] == 1
        assert stats["swarm_role_distribution"]["worker"] == 2

    def test_clear_data(self):
        eng = SwarmIntelligenceEngine()
        r = eng.add_record(agent_id="a1")
        eng.process(r.id)
        result = eng.clear_data()
        assert result == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


class TestSwarmDomainMethods:
    def test_evaluate_swarm_coordination(self):
        eng = SwarmIntelligenceEngine()
        eng.add_record(
            swarm_id="swarm-1",
            agent_id="a1",
            task_completion_rate=0.95,
            response_time_seconds=1.0,
            messages_sent=10,
            swarm_health=SwarmHealth.OPTIMAL,
        )
        eng.add_record(
            swarm_id="swarm-1",
            agent_id="a2",
            task_completion_rate=0.85,
            response_time_seconds=2.0,
            messages_sent=20,
            swarm_health=SwarmHealth.OPTIMAL,
        )
        results = eng.evaluate_swarm_coordination()
        assert len(results) == 1
        assert results[0]["swarm_id"] == "swarm-1"
        assert results[0]["agent_count"] == 2
        assert results[0]["total_messages"] == 30
        assert results[0]["rating"] == "excellent"

    def test_evaluate_swarm_coordination_empty(self):
        eng = SwarmIntelligenceEngine()
        assert eng.evaluate_swarm_coordination() == []

    def test_identify_bottleneck_agents(self):
        eng = SwarmIntelligenceEngine()
        # Bottleneck agent: low completion, high response time
        eng.add_record(
            agent_id="slow-agent",
            task_completion_rate=0.2,
            response_time_seconds=120.0,
            tasks_assigned=10,
            tasks_completed=2,
        )
        # Good agent
        eng.add_record(
            agent_id="good-agent",
            task_completion_rate=0.95,
            response_time_seconds=1.0,
            tasks_assigned=10,
            tasks_completed=10,
        )
        results = eng.identify_bottleneck_agents()
        assert len(results) == 1
        assert results[0]["agent_id"] == "slow-agent"
        assert results[0]["bottleneck_reason"] == "slow_response"

    def test_identify_bottleneck_agents_empty(self):
        eng = SwarmIntelligenceEngine()
        assert eng.identify_bottleneck_agents() == []

    def test_identify_bottleneck_agents_none(self):
        eng = SwarmIntelligenceEngine()
        eng.add_record(
            agent_id="good",
            task_completion_rate=0.9,
            response_time_seconds=1.0,
            tasks_assigned=10,
            tasks_completed=9,
        )
        assert eng.identify_bottleneck_agents() == []

    def test_optimize_task_distribution(self):
        eng = SwarmIntelligenceEngine()
        eng.add_record(
            coordination_pattern=CoordinationPattern.CONSENSUS,
            agent_id="a1",
            task_completion_rate=0.9,
            response_time_seconds=2.0,
            tasks_assigned=5,
            tasks_completed=4,
        )
        eng.add_record(
            coordination_pattern=CoordinationPattern.AUCTION,
            agent_id="a2",
            task_completion_rate=0.4,
            response_time_seconds=50.0,
            tasks_assigned=15,
            tasks_completed=6,
        )
        results = eng.optimize_task_distribution()
        assert len(results) == 2
        # Sorted by completion rate desc
        assert results[0]["coordination_pattern"] == "consensus"

    def test_optimize_task_distribution_empty(self):
        eng = SwarmIntelligenceEngine()
        assert eng.optimize_task_distribution() == []

    def test_optimize_task_distribution_balanced(self):
        eng = SwarmIntelligenceEngine()
        eng.add_record(
            coordination_pattern=CoordinationPattern.DELEGATION,
            agent_id="a1",
            task_completion_rate=0.95,
            response_time_seconds=1.0,
            tasks_assigned=3,
            tasks_completed=3,
        )
        results = eng.optimize_task_distribution()
        assert "Task distribution is balanced" in results[0]["improvements"]


# ===========================================================================
# 3. LearningFeedbackLoopEngine
# ===========================================================================


class TestFeedbackEnums:
    def test_feedback_type_values(self):
        assert FeedbackType.POSITIVE == "positive"
        assert FeedbackType.NEGATIVE == "negative"
        assert FeedbackType.NEUTRAL == "neutral"
        assert FeedbackType.CORRECTIVE == "corrective"

    def test_learning_phase_values(self):
        assert LearningPhase.EXPLORATION == "exploration"
        assert LearningPhase.EXPLOITATION == "exploitation"
        assert LearningPhase.EVALUATION == "evaluation"

    def test_convergence_status_values(self):
        assert ConvergenceStatus.CONVERGING == "converging"
        assert ConvergenceStatus.DIVERGING == "diverging"
        assert ConvergenceStatus.OSCILLATING == "oscillating"
        assert ConvergenceStatus.CONVERGED == "converged"


class TestFeedbackModels:
    def test_record_defaults(self):
        r = LearningFeedbackRecord()
        assert r.id
        assert r.agent_id == ""
        assert r.model_id == ""
        assert r.feedback_type == FeedbackType.NEUTRAL
        assert r.learning_phase == LearningPhase.EXPLORATION
        assert r.convergence_status == ConvergenceStatus.DIVERGING
        assert r.feedback_score == 0.0
        assert r.exploration_rate == 0.0
        assert r.accuracy_delta == 0.0
        assert r.iteration_count == 0
        assert r.reward_signal == 0.0
        assert r.created_at > 0

    def test_analysis_defaults(self):
        a = LearningFeedbackAnalysis()
        assert a.id
        assert a.agent_id == ""
        assert a.learning_phase == LearningPhase.EXPLORATION
        assert a.convergence_status == ConvergenceStatus.DIVERGING
        assert a.learning_efficiency == 0.0
        assert a.created_at > 0

    def test_report_defaults(self):
        r = LearningFeedbackReport()
        assert r.id
        assert r.total_records == 0
        assert r.total_analyses == 0
        assert r.avg_feedback_score == 0.0
        assert r.by_feedback_type == {}
        assert r.by_learning_phase == {}
        assert r.by_convergence_status == {}
        assert r.diverging_agents == []
        assert r.recommendations == []
        assert r.generated_at > 0


class TestFeedbackAddRecord:
    def test_basic(self):
        eng = LearningFeedbackLoopEngine()
        r = eng.add_record(
            agent_id="agent-1",
            model_id="model-v2",
            feedback_type=FeedbackType.POSITIVE,
            learning_phase=LearningPhase.EXPLOITATION,
            convergence_status=ConvergenceStatus.CONVERGING,
            feedback_score=0.85,
            exploration_rate=0.3,
            accuracy_delta=0.05,
            iteration_count=100,
            reward_signal=0.9,
        )
        assert r.agent_id == "agent-1"
        assert r.feedback_type == FeedbackType.POSITIVE
        assert r.feedback_score == 0.85

    def test_defaults(self):
        eng = LearningFeedbackLoopEngine()
        r = eng.add_record()
        assert r.agent_id == ""
        assert r.feedback_type == FeedbackType.NEUTRAL

    def test_ring_buffer_eviction(self):
        eng = LearningFeedbackLoopEngine(max_records=3)
        ids = []
        for i in range(5):
            rec = eng.add_record(agent_id=f"a-{i}")
            ids.append(rec.id)
        assert len(eng._records) == 3
        remaining = [r.id for r in eng._records]
        assert ids[0] not in remaining
        assert ids[4] in remaining


class TestFeedbackProcess:
    def test_process_found_converged(self):
        eng = LearningFeedbackLoopEngine()
        r = eng.add_record(
            agent_id="agent-1",
            convergence_status=ConvergenceStatus.CONVERGED,
            feedback_score=0.8,
            accuracy_delta=0.1,
        )
        result = eng.process(r.id)
        assert isinstance(result, LearningFeedbackAnalysis)
        assert result.agent_id == "agent-1"
        # 0.8*0.5 + 1.0*0.3 + 0.1*0.2 = 0.72
        assert result.learning_efficiency == round(0.8 * 0.5 + 1.0 * 0.3 + 0.1 * 0.2, 4)

    def test_process_found_diverging(self):
        eng = LearningFeedbackLoopEngine()
        r = eng.add_record(
            convergence_status=ConvergenceStatus.DIVERGING,
            feedback_score=0.4,
            accuracy_delta=-0.1,  # negative, max(..., 0.0) = 0.0
        )
        result = eng.process(r.id)
        assert isinstance(result, LearningFeedbackAnalysis)
        # 0.4*0.5 + 0.1*0.3 + 0.0*0.2 = 0.23
        assert result.learning_efficiency == round(0.4 * 0.5 + 0.1 * 0.3, 4)

    def test_process_not_found(self):
        eng = LearningFeedbackLoopEngine()
        result = eng.process("nonexistent")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"


class TestFeedbackReport:
    def test_generate_report_populated(self):
        eng = LearningFeedbackLoopEngine()
        eng.add_record(
            agent_id="agent-1",
            feedback_type=FeedbackType.POSITIVE,
            learning_phase=LearningPhase.EXPLOITATION,
            convergence_status=ConvergenceStatus.CONVERGED,
            feedback_score=0.9,
        )
        eng.add_record(
            agent_id="agent-2",
            feedback_type=FeedbackType.NEGATIVE,
            learning_phase=LearningPhase.EXPLORATION,
            convergence_status=ConvergenceStatus.DIVERGING,
            feedback_score=0.2,
        )
        report = eng.generate_report()
        assert isinstance(report, LearningFeedbackReport)
        assert report.total_records == 2
        assert report.by_feedback_type["positive"] == 1
        assert report.by_feedback_type["negative"] == 1
        assert "agent-2" in report.diverging_agents

    def test_generate_report_empty(self):
        eng = LearningFeedbackLoopEngine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert report.avg_feedback_score == 0.0

    def test_generate_report_healthy(self):
        eng = LearningFeedbackLoopEngine()
        eng.add_record(
            convergence_status=ConvergenceStatus.CONVERGED,
            feedback_score=0.9,
        )
        report = eng.generate_report()
        assert any("normal parameters" in r for r in report.recommendations)

    def test_generate_report_low_score(self):
        eng = LearningFeedbackLoopEngine()
        eng.add_record(feedback_score=0.1)
        eng.add_record(feedback_score=0.2)
        report = eng.generate_report()
        assert any("below 0.5" in r for r in report.recommendations)


class TestFeedbackStats:
    def test_get_stats_empty(self):
        eng = LearningFeedbackLoopEngine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0
        assert stats["total_analyses"] == 0
        assert stats["feedback_type_distribution"] == {}

    def test_get_stats_populated(self):
        eng = LearningFeedbackLoopEngine()
        eng.add_record(feedback_type=FeedbackType.POSITIVE)
        eng.add_record(feedback_type=FeedbackType.NEGATIVE)
        eng.add_record(feedback_type=FeedbackType.POSITIVE)
        stats = eng.get_stats()
        assert stats["total_records"] == 3
        assert stats["feedback_type_distribution"]["positive"] == 2
        assert stats["feedback_type_distribution"]["negative"] == 1

    def test_clear_data(self):
        eng = LearningFeedbackLoopEngine()
        r = eng.add_record(agent_id="a1")
        eng.process(r.id)
        result = eng.clear_data()
        assert result == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


class TestFeedbackDomainMethods:
    def test_track_learning_progress(self):
        eng = LearningFeedbackLoopEngine()
        eng.add_record(
            agent_id="agent-1",
            accuracy_delta=0.05,
            reward_signal=0.8,
            iteration_count=10,
            learning_phase=LearningPhase.EXPLORATION,
            convergence_status=ConvergenceStatus.CONVERGING,
        )
        eng.add_record(
            agent_id="agent-1",
            accuracy_delta=0.03,
            reward_signal=0.85,
            iteration_count=20,
            learning_phase=LearningPhase.EXPLOITATION,
            convergence_status=ConvergenceStatus.CONVERGED,
        )
        results = eng.track_learning_progress()
        assert len(results) == 1
        assert results[0]["agent_id"] == "agent-1"
        assert results[0]["total_iterations"] == 30
        assert results[0]["trend"] == "improving"
        assert results[0]["latest_convergence"] == "converged"

    def test_track_learning_progress_empty(self):
        eng = LearningFeedbackLoopEngine()
        assert eng.track_learning_progress() == []

    def test_track_learning_progress_declining(self):
        eng = LearningFeedbackLoopEngine()
        eng.add_record(agent_id="a1", accuracy_delta=-0.1)
        eng.add_record(agent_id="a1", accuracy_delta=-0.05)
        results = eng.track_learning_progress()
        assert results[0]["trend"] == "declining"

    def test_evaluate_feedback_quality(self):
        eng = LearningFeedbackLoopEngine()
        eng.add_record(
            feedback_type=FeedbackType.POSITIVE,
            feedback_score=0.9,
            accuracy_delta=0.1,
            reward_signal=0.8,
            convergence_status=ConvergenceStatus.CONVERGED,
        )
        eng.add_record(
            feedback_type=FeedbackType.NEGATIVE,
            feedback_score=0.2,
            accuracy_delta=-0.05,
            reward_signal=0.1,
            convergence_status=ConvergenceStatus.DIVERGING,
        )
        results = eng.evaluate_feedback_quality()
        assert len(results) == 2
        # Sorted by avg_feedback_score desc, positive first
        assert results[0]["feedback_type"] == "positive"
        assert results[0]["quality_rating"] == "high"
        assert results[1]["feedback_type"] == "negative"
        assert results[1]["quality_rating"] == "low"

    def test_evaluate_feedback_quality_empty(self):
        eng = LearningFeedbackLoopEngine()
        assert eng.evaluate_feedback_quality() == []

    def test_optimize_exploration_rate_converged(self):
        eng = LearningFeedbackLoopEngine()
        eng.add_record(
            agent_id="a1",
            exploration_rate=0.5,
            convergence_status=ConvergenceStatus.CONVERGED,
            accuracy_delta=0.01,
        )
        results = eng.optimize_exploration_rate()
        assert len(results) == 1
        assert results[0]["agent_id"] == "a1"
        assert results[0]["optimal_exploration_rate"] < results[0]["current_exploration_rate"]
        assert "reduce exploration" in results[0]["reason"]

    def test_optimize_exploration_rate_diverging(self):
        eng = LearningFeedbackLoopEngine()
        eng.add_record(
            agent_id="a1",
            exploration_rate=0.3,
            convergence_status=ConvergenceStatus.DIVERGING,
        )
        results = eng.optimize_exploration_rate()
        assert results[0]["optimal_exploration_rate"] > results[0]["current_exploration_rate"]
        assert "increase exploration" in results[0]["reason"]

    def test_optimize_exploration_rate_empty(self):
        eng = LearningFeedbackLoopEngine()
        assert eng.optimize_exploration_rate() == []


# ===========================================================================
# 4. AgentKnowledgeDistillationEngine
# ===========================================================================


class TestDistillationEnums:
    def test_distillation_method_values(self):
        assert DistillationMethod.RESPONSE_MATCHING == "response_matching"
        assert DistillationMethod.FEATURE_TRANSFER == "feature_transfer"
        assert DistillationMethod.BEHAVIOR_CLONING == "behavior_cloning"
        assert DistillationMethod.ENSEMBLE_AVERAGING == "ensemble_averaging"

    def test_knowledge_type_values(self):
        assert KnowledgeType.INVESTIGATION_PATTERNS == "investigation_patterns"
        assert KnowledgeType.REMEDIATION_STRATEGIES == "remediation_strategies"
        assert KnowledgeType.THREAT_SIGNATURES == "threat_signatures"
        assert KnowledgeType.ROUTING_RULES == "routing_rules"

    def test_transfer_outcome_values(self):
        assert TransferOutcome.SUCCESSFUL == "successful"
        assert TransferOutcome.PARTIAL == "partial"
        assert TransferOutcome.FAILED == "failed"
        assert TransferOutcome.REGRESSED == "regressed"


class TestDistillationModels:
    def test_record_defaults(self):
        r = DistillationRecord()
        assert r.id
        assert r.name == ""
        assert r.distillation_method == DistillationMethod.RESPONSE_MATCHING
        assert r.knowledge_type == KnowledgeType.INVESTIGATION_PATTERNS
        assert r.transfer_outcome == TransferOutcome.SUCCESSFUL
        assert r.score == 0.0
        assert r.expert_agent == ""
        assert r.student_agent == ""
        assert r.service == ""
        assert r.team == ""
        assert r.created_at > 0

    def test_analysis_defaults(self):
        a = DistillationAnalysis()
        assert a.id
        assert a.name == ""
        assert a.distillation_method == DistillationMethod.RESPONSE_MATCHING
        assert a.analysis_score == 0.0
        assert a.threshold == 0.0
        assert a.breached is False
        assert a.created_at > 0

    def test_report_defaults(self):
        r = DistillationReport()
        assert r.id
        assert r.total_records == 0
        assert r.total_analyses == 0
        assert r.gap_count == 0
        assert r.avg_score == 0.0
        assert r.by_method == {}
        assert r.by_knowledge_type == {}
        assert r.by_outcome == {}
        assert r.top_gaps == []
        assert r.recommendations == []
        assert r.generated_at > 0


class TestDistillationAddRecord:
    def test_basic(self):
        eng = AgentKnowledgeDistillationEngine()
        r = eng.add_record(
            name="transfer-001",
            distillation_method=DistillationMethod.BEHAVIOR_CLONING,
            knowledge_type=KnowledgeType.THREAT_SIGNATURES,
            transfer_outcome=TransferOutcome.SUCCESSFUL,
            score=85.0,
            expert_agent="expert-1",
            student_agent="student-1",
            service="auth-svc",
            team="security",
        )
        assert r.name == "transfer-001"
        assert r.score == 85.0
        assert r.expert_agent == "expert-1"

    def test_ring_buffer_eviction(self):
        eng = AgentKnowledgeDistillationEngine(max_records=3)
        for i in range(5):
            eng.add_record(name=f"t-{i}")
        assert len(eng._records) == 3

    def test_get_record(self):
        eng = AgentKnowledgeDistillationEngine()
        r = eng.add_record(name="test")
        assert eng.get_record(r.id) is not None
        assert eng.get_record("nonexistent") is None

    def test_list_records_filter_by_method(self):
        eng = AgentKnowledgeDistillationEngine()
        eng.add_record(name="a", distillation_method=DistillationMethod.RESPONSE_MATCHING)
        eng.add_record(name="b", distillation_method=DistillationMethod.FEATURE_TRANSFER)
        results = eng.list_records(distillation_method=DistillationMethod.RESPONSE_MATCHING)
        assert len(results) == 1

    def test_list_records_filter_by_knowledge_type(self):
        eng = AgentKnowledgeDistillationEngine()
        eng.add_record(name="a", knowledge_type=KnowledgeType.THREAT_SIGNATURES)
        eng.add_record(name="b", knowledge_type=KnowledgeType.ROUTING_RULES)
        results = eng.list_records(knowledge_type=KnowledgeType.THREAT_SIGNATURES)
        assert len(results) == 1

    def test_list_records_filter_by_team(self):
        eng = AgentKnowledgeDistillationEngine()
        eng.add_record(name="a", team="security")
        eng.add_record(name="b", team="platform")
        assert len(eng.list_records(team="security")) == 1

    def test_list_records_limit(self):
        eng = AgentKnowledgeDistillationEngine()
        for i in range(10):
            eng.add_record(name=f"t-{i}")
        assert len(eng.list_records(limit=3)) == 3


class TestDistillationAnalysisMethod:
    def test_add_analysis(self):
        eng = AgentKnowledgeDistillationEngine()
        a = eng.add_analysis(name="test", analysis_score=75.0, breached=True)
        assert a.name == "test"
        assert a.analysis_score == 75.0
        assert a.breached is True

    def test_analysis_eviction(self):
        eng = AgentKnowledgeDistillationEngine(max_records=2)
        for i in range(5):
            eng.add_analysis(name=f"a-{i}")
        assert len(eng._analyses) == 2


class TestDistillationDomainMethods:
    def test_identify_distillation_candidates(self):
        eng = AgentKnowledgeDistillationEngine()
        eng.add_record(name="t1", expert_agent="exp-1", student_agent="stu-1", score=90.0)
        eng.add_record(name="t2", expert_agent="exp-1", student_agent="stu-1", score=80.0)
        eng.add_record(name="t3", expert_agent="exp-2", student_agent="stu-2", score=30.0)
        results = eng.identify_distillation_candidates()
        assert len(results) == 2
        assert results[0]["expert_agent"] == "exp-1"
        assert results[0]["potential"] == "high"
        assert results[1]["potential"] == "low"

    def test_identify_distillation_candidates_empty(self):
        eng = AgentKnowledgeDistillationEngine()
        assert eng.identify_distillation_candidates() == []

    def test_measure_transfer_effectiveness(self):
        eng = AgentKnowledgeDistillationEngine()
        eng.add_record(name="t1", transfer_outcome=TransferOutcome.SUCCESSFUL, score=90.0)
        eng.add_record(name="t2", transfer_outcome=TransferOutcome.SUCCESSFUL, score=85.0)
        eng.add_record(name="t3", transfer_outcome=TransferOutcome.FAILED, score=20.0)
        result = eng.measure_transfer_effectiveness()
        assert result["total_transfers"] == 3
        assert result["success_rate"] == 66.67
        assert "successful" in result["by_outcome"]

    def test_measure_transfer_effectiveness_empty(self):
        eng = AgentKnowledgeDistillationEngine()
        result = eng.measure_transfer_effectiveness()
        assert result["total_transfers"] == 0
        assert result["success_rate"] == 0.0

    def test_recommend_distillation_strategy(self):
        eng = AgentKnowledgeDistillationEngine()
        eng.add_record(
            name="t1",
            knowledge_type=KnowledgeType.INVESTIGATION_PATTERNS,
            distillation_method=DistillationMethod.BEHAVIOR_CLONING,
            score=90.0,
        )
        eng.add_record(
            name="t2",
            knowledge_type=KnowledgeType.INVESTIGATION_PATTERNS,
            distillation_method=DistillationMethod.RESPONSE_MATCHING,
            score=60.0,
        )
        results = eng.recommend_distillation_strategy()
        assert len(results) == 1
        assert results[0]["recommended_method"] == "behavior_cloning"

    def test_recommend_distillation_strategy_empty(self):
        eng = AgentKnowledgeDistillationEngine()
        assert eng.recommend_distillation_strategy() == []


class TestDistillationReportStats:
    def test_generate_report_populated(self):
        eng = AgentKnowledgeDistillationEngine(threshold=50.0)
        eng.add_record(name="t1", score=30.0)
        eng.add_record(name="t2", score=80.0)
        report = eng.generate_report()
        assert isinstance(report, DistillationReport)
        assert report.total_records == 2
        assert report.gap_count == 1
        assert len(report.recommendations) > 0
        assert "t1" in report.top_gaps

    def test_generate_report_empty(self):
        eng = AgentKnowledgeDistillationEngine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert "healthy" in report.recommendations[0]

    def test_generate_report_all_above_threshold(self):
        eng = AgentKnowledgeDistillationEngine(threshold=50.0)
        eng.add_record(name="t1", score=90.0)
        eng.add_record(name="t2", score=80.0)
        report = eng.generate_report()
        assert report.gap_count == 0
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self):
        eng = AgentKnowledgeDistillationEngine()
        eng.add_record(name="t1")
        eng.add_analysis(name="a1")
        result = eng.clear_data()
        assert result == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0

    def test_get_stats_empty(self):
        eng = AgentKnowledgeDistillationEngine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0
        assert stats["total_analyses"] == 0
        assert stats["threshold"] == 50.0

    def test_get_stats_populated(self):
        eng = AgentKnowledgeDistillationEngine()
        eng.add_record(name="t1", service="auth-svc", team="security")
        eng.add_record(name="t2", service="api-gw", team="platform")
        stats = eng.get_stats()
        assert stats["total_records"] == 2
        assert stats["unique_teams"] == 2
        assert stats["unique_services"] == 2
        assert stats["method_distribution"]["response_matching"] == 2
