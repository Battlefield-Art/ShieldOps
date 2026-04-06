"""Tests for Phase 137 engines (kill chain, SOAR response, resource governor, investigation pattern, evolution tracker)."""  # noqa: E501

from __future__ import annotations

import pytest

from shieldops.analytics.agent_evolution_tracker_engine import (
    AgentEvolutionTrackerAnalysis,
    AgentEvolutionTrackerEngine,
    AgentEvolutionTrackerRecord,
    AgentEvolutionTrackerReport,
    CapabilityDomain,
    EvolutionPhase,
    EvolutionTrend,
)
from shieldops.analytics.agent_resource_governor_engine import (
    AgentResourceGovernorAnalysis,
    AgentResourceGovernorEngine,
    AgentResourceGovernorRecord,
    AgentResourceGovernorReport,
    BudgetPeriod,
    LimitScope,
    ResourcePolicy,
)
from shieldops.analytics.investigation_pattern_engine import (
    InvestigationPatternAnalysis,
    InvestigationPatternEngine,
    InvestigationPatternRecord,
    InvestigationPatternReport,
    MatchQuality,
    PatternConfidence,
    PatternType,
)
from shieldops.security.kill_chain_tracker_engine import (
    DetectionPoint,
    KillChainPhase,
    KillChainTrackerAnalysis,
    KillChainTrackerEngine,
    KillChainTrackerRecord,
    KillChainTrackerReport,
    ProgressionRisk,
)
from shieldops.security.soar_response_tracker_engine import (
    AutomationLevel,
    ResponseEffectiveness,
    ResponsePhase,
    SoarResponseTrackerAnalysis,
    SoarResponseTrackerEngine,
    SoarResponseTrackerRecord,
    SoarResponseTrackerReport,
)

# ========== KillChainTrackerEngine ==========


class TestKillChainEnums:
    def test_kill_chain_phase_values(self):
        assert KillChainPhase.RECONNAISSANCE == "reconnaissance"
        assert KillChainPhase.WEAPONIZATION == "weaponization"
        assert KillChainPhase.DELIVERY == "delivery"
        assert KillChainPhase.EXPLOITATION == "exploitation"
        assert KillChainPhase.INSTALLATION == "installation"
        assert KillChainPhase.COMMAND_AND_CONTROL == "command_and_control"
        assert KillChainPhase.ACTIONS_ON_OBJECTIVES == "actions_on_objectives"

    def test_detection_point_values(self):
        assert DetectionPoint.NETWORK == "network"
        assert DetectionPoint.ENDPOINT == "endpoint"
        assert DetectionPoint.IDENTITY == "identity"
        assert DetectionPoint.CLOUD == "cloud"

    def test_progression_risk_values(self):
        assert ProgressionRisk.CONTAINED == "contained"
        assert ProgressionRisk.ADVANCING == "advancing"
        assert ProgressionRisk.CRITICAL == "critical"


class TestKillChainModels:
    def test_record_defaults(self):
        r = KillChainTrackerRecord()
        assert r.kill_chain_phase == KillChainPhase.RECONNAISSANCE
        assert r.detection_point == DetectionPoint.NETWORK
        assert r.score == 0.0

    def test_analysis_defaults(self):
        a = KillChainTrackerAnalysis()
        assert a.breached is False

    def test_report_defaults(self):
        r = KillChainTrackerReport()
        assert r.by_kill_chain_phase == {}


class TestKillChainEngine:
    @pytest.fixture()
    def engine(self):
        return KillChainTrackerEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._max_records == 100

    def test_add_record(self, engine):
        r = engine.add_record(name="attack-1", service="svc-a", score=80)
        assert r.name == "attack-1"

    def test_get_record(self, engine):
        r = engine.add_record(name="test")
        assert engine.get_record(r.id) is not None

    def test_get_record_not_found(self, engine):
        assert engine.get_record("nope") is None

    def test_list_records_filter_phase(self, engine):
        engine.add_record(name="a", kill_chain_phase=KillChainPhase.DELIVERY)
        engine.add_record(name="b", kill_chain_phase=KillChainPhase.EXPLOITATION)
        results = engine.list_records(kill_chain_phase=KillChainPhase.DELIVERY)
        assert len(results) == 1

    def test_list_records_filter_detection(self, engine):
        engine.add_record(name="a", detection_point=DetectionPoint.ENDPOINT)
        engine.add_record(name="b", detection_point=DetectionPoint.CLOUD)
        results = engine.list_records(detection_point=DetectionPoint.ENDPOINT)
        assert len(results) == 1

    def test_list_records_filter_team(self, engine):
        engine.add_record(name="a", team="sec")
        engine.add_record(name="b", team="ops")
        assert len(engine.list_records(team="sec")) == 1

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r-{i}")
        assert len(engine._records) == 100

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="a1", analysis_score=90)
        assert a.analysis_score == 90

    def test_track_attack_progression(self, engine):
        engine.add_record(
            name="a",
            attacker_id="atk-1",
            kill_chain_phase=KillChainPhase.RECONNAISSANCE,
            service="s1",
            event_count=5,
        )
        engine.add_record(
            name="b",
            attacker_id="atk-1",
            kill_chain_phase=KillChainPhase.EXPLOITATION,
            service="s2",
            event_count=3,
        )
        results = engine.track_attack_progression()
        assert len(results) == 1
        assert results[0]["progression_depth"] == 4  # exploitation is index 3, +1

    def test_identify_lateral_movement(self, engine):
        engine.add_record(name="a", attacker_id="atk-1", service="svc-a")
        engine.add_record(name="b", attacker_id="atk-1", service="svc-b")
        lateral = engine.identify_lateral_movement()
        assert len(lateral) == 1
        assert lateral[0]["lateral_spread"] == 2

    def test_identify_lateral_movement_single_service(self, engine):
        engine.add_record(name="a", attacker_id="atk-1", service="svc-a")
        engine.add_record(name="b", attacker_id="atk-1", service="svc-a")
        lateral = engine.identify_lateral_movement()
        assert len(lateral) == 0

    def test_predict_next_phase(self, engine):
        engine.add_record(name="a", attacker_id="atk-1", kill_chain_phase=KillChainPhase.DELIVERY)
        preds = engine.predict_next_phase()
        assert len(preds) == 1
        assert preds[0]["predicted_next_phase"] == "exploitation"

    def test_predict_next_phase_final(self, engine):
        engine.add_record(
            name="a", attacker_id="atk-1", kill_chain_phase=KillChainPhase.ACTIONS_ON_OBJECTIVES
        )
        preds = engine.predict_next_phase()
        assert len(preds) == 0

    def test_identify_gaps(self, engine):
        engine.add_record(name="low", score=10)
        engine.add_record(name="high", score=90)
        assert len(engine.identify_gaps()) == 1

    def test_rank_by_score(self, engine):
        engine.add_record(name="a", service="s1", score=20)
        engine.add_record(name="b", service="s2", score=80)
        ranked = engine.rank_by_score()
        assert ranked[0]["service"] == "s1"

    def test_process_found(self, engine):
        engine.add_record(name="k1", score=70)
        assert engine.process("k1")["status"] == "processed"

    def test_process_not_found(self, engine):
        assert engine.process("x")["status"] == "not_found"

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=20)
        engine.add_record(name="b", score=80)
        report = engine.generate_report()
        assert isinstance(report, KillChainTrackerReport)
        assert report.total_records == 2

    def test_generate_report_healthy(self, engine):
        engine.add_record(name="a", score=90)
        report = engine.generate_report()
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self, engine):
        engine.add_record(name="a")
        engine.clear_data()
        assert len(engine._records) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1


# ========== SoarResponseTrackerEngine ==========


class TestSoarResponseEnums:
    def test_response_phase_values(self):
        assert ResponsePhase.CONTAINMENT == "containment"
        assert ResponsePhase.ERADICATION == "eradication"
        assert ResponsePhase.RECOVERY == "recovery"
        assert ResponsePhase.LESSONS_LEARNED == "lessons_learned"

    def test_automation_level_values(self):
        assert AutomationLevel.FULL_AUTO == "full_auto"
        assert AutomationLevel.SEMI_AUTO == "semi_auto"
        assert AutomationLevel.MANUAL == "manual"

    def test_response_effectiveness_values(self):
        assert ResponseEffectiveness.EFFECTIVE == "effective"
        assert ResponseEffectiveness.PARTIAL == "partial"
        assert ResponseEffectiveness.INEFFECTIVE == "ineffective"


class TestSoarResponseModels:
    def test_record_defaults(self):
        r = SoarResponseTrackerRecord()
        assert r.response_phase == ResponsePhase.CONTAINMENT
        assert r.response_time_seconds == 0.0

    def test_analysis_defaults(self):
        a = SoarResponseTrackerAnalysis()
        assert a.breached is False

    def test_report_defaults(self):
        r = SoarResponseTrackerReport()
        assert r.by_response_phase == {}


class TestSoarResponseEngine:
    @pytest.fixture()
    def engine(self):
        return SoarResponseTrackerEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._max_records == 100

    def test_add_record(self, engine):
        r = engine.add_record(name="resp-1", service="svc-a", score=80)
        assert r.name == "resp-1"

    def test_get_record(self, engine):
        r = engine.add_record(name="test")
        assert engine.get_record(r.id) is not None

    def test_get_record_not_found(self, engine):
        assert engine.get_record("nope") is None

    def test_list_records_filter_phase(self, engine):
        engine.add_record(name="a", response_phase=ResponsePhase.CONTAINMENT)
        engine.add_record(name="b", response_phase=ResponsePhase.RECOVERY)
        results = engine.list_records(response_phase=ResponsePhase.CONTAINMENT)
        assert len(results) == 1

    def test_list_records_filter_automation(self, engine):
        engine.add_record(name="a", automation_level=AutomationLevel.FULL_AUTO)
        engine.add_record(name="b", automation_level=AutomationLevel.MANUAL)
        results = engine.list_records(automation_level=AutomationLevel.FULL_AUTO)
        assert len(results) == 1

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r-{i}")
        assert len(engine._records) == 100

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="a1")
        assert a.name == "a1"

    def test_compute_mean_time_to_contain(self, engine):
        engine.add_record(
            name="a",
            service="svc-a",
            response_phase=ResponsePhase.CONTAINMENT,
            response_time_seconds=300,
            score=80,
        )
        engine.add_record(
            name="b",
            service="svc-a",
            response_phase=ResponsePhase.CONTAINMENT,
            response_time_seconds=600,
            score=70,
        )
        results = engine.compute_mean_time_to_contain()
        assert len(results) == 1
        assert results[0]["mttc_seconds"] == 450.0

    def test_compute_mttc_skips_non_containment(self, engine):
        engine.add_record(
            name="a",
            service="svc-a",
            response_phase=ResponsePhase.RECOVERY,
            response_time_seconds=100,
        )
        results = engine.compute_mean_time_to_contain()
        assert len(results) == 0

    def test_identify_slow_response_phases(self, engine):
        engine.add_record(
            name="a", response_phase=ResponsePhase.CONTAINMENT, response_time_seconds=100
        )
        engine.add_record(
            name="b", response_phase=ResponsePhase.RECOVERY, response_time_seconds=500
        )
        slow = engine.identify_slow_response_phases()
        assert len(slow) >= 1
        assert slow[0]["phase"] == "recovery"

    def test_recommend_automation_upgrades(self, engine):
        engine.add_record(
            name="a",
            service="svc-a",
            automation_level=AutomationLevel.MANUAL,
            response_time_seconds=5000,
            response_effectiveness=ResponseEffectiveness.INEFFECTIVE,
        )
        recs = engine.recommend_automation_upgrades()
        assert len(recs) == 1
        assert recs[0]["priority"] == "high"

    def test_recommend_automation_no_manual(self, engine):
        engine.add_record(name="a", service="svc-a", automation_level=AutomationLevel.FULL_AUTO)
        recs = engine.recommend_automation_upgrades()
        assert len(recs) == 0

    def test_identify_gaps(self, engine):
        engine.add_record(name="low", score=10)
        engine.add_record(name="high", score=90)
        assert len(engine.identify_gaps()) == 1

    def test_process_found(self, engine):
        engine.add_record(name="k1", score=70)
        assert engine.process("k1")["status"] == "processed"

    def test_process_not_found(self, engine):
        assert engine.process("x")["status"] == "not_found"

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=20)
        report = engine.generate_report()
        assert isinstance(report, SoarResponseTrackerReport)
        assert report.total_records == 1

    def test_generate_report_healthy(self, engine):
        engine.add_record(name="a", score=90)
        report = engine.generate_report()
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self, engine):
        engine.add_record(name="a")
        engine.clear_data()
        assert len(engine._records) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1

    def test_analyze_distribution(self, engine):
        engine.add_record(name="a", response_phase=ResponsePhase.CONTAINMENT, score=80)
        dist = engine.analyze_distribution()
        assert "containment" in dist

    def test_rank_by_score(self, engine):
        engine.add_record(name="a", service="s1", score=20)
        engine.add_record(name="b", service="s2", score=80)
        ranked = engine.rank_by_score()
        assert ranked[0]["service"] == "s1"


# ========== AgentResourceGovernorEngine ==========


class TestResourceGovernorEnums:
    def test_resource_policy_values(self):
        assert ResourcePolicy.ENFORCE == "enforce"
        assert ResourcePolicy.WARN == "warn"
        assert ResourcePolicy.MONITOR == "monitor"

    def test_limit_scope_values(self):
        assert LimitScope.PER_AGENT == "per_agent"
        assert LimitScope.PER_TENANT == "per_tenant"
        assert LimitScope.GLOBAL == "global"

    def test_budget_period_values(self):
        assert BudgetPeriod.HOURLY == "hourly"
        assert BudgetPeriod.DAILY == "daily"
        assert BudgetPeriod.WEEKLY == "weekly"
        assert BudgetPeriod.MONTHLY == "monthly"


class TestResourceGovernorModels:
    def test_record_defaults(self):
        r = AgentResourceGovernorRecord()
        assert r.resource_policy == ResourcePolicy.MONITOR
        assert r.usage_amount == 0.0

    def test_analysis_defaults(self):
        a = AgentResourceGovernorAnalysis()
        assert a.breached is False

    def test_report_defaults(self):
        r = AgentResourceGovernorReport()
        assert r.by_resource_policy == {}


class TestResourceGovernorEngine:
    @pytest.fixture()
    def engine(self):
        return AgentResourceGovernorEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._max_records == 100

    def test_add_record(self, engine):
        r = engine.add_record(name="agent-1", service="svc-a", score=70)
        assert r.name == "agent-1"

    def test_get_record(self, engine):
        r = engine.add_record(name="test")
        assert engine.get_record(r.id) is not None

    def test_get_record_not_found(self, engine):
        assert engine.get_record("nope") is None

    def test_list_records_filter_policy(self, engine):
        engine.add_record(name="a", resource_policy=ResourcePolicy.ENFORCE)
        engine.add_record(name="b", resource_policy=ResourcePolicy.MONITOR)
        results = engine.list_records(resource_policy=ResourcePolicy.ENFORCE)
        assert len(results) == 1

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r-{i}")
        assert len(engine._records) == 100

    def test_enforce_resource_limits(self, engine):
        engine.add_record(
            name="a",
            service="s1",
            resource_policy=ResourcePolicy.ENFORCE,
            usage_amount=150,
            budget_limit=100,
        )
        violations = engine.enforce_resource_limits()
        assert len(violations) == 1
        assert violations[0]["action"] == "throttled"
        assert violations[0]["utilization_pct"] == 150.0

    def test_enforce_limits_no_violation(self, engine):
        engine.add_record(name="a", usage_amount=50, budget_limit=100)
        assert len(engine.enforce_resource_limits()) == 0

    def test_enforce_limits_warn_action(self, engine):
        engine.add_record(
            name="a", resource_policy=ResourcePolicy.WARN, usage_amount=200, budget_limit=100
        )
        violations = engine.enforce_resource_limits()
        assert violations[0]["action"] == "warned"

    def test_detect_budget_violations(self, engine):
        engine.add_record(name="a", service="s1", usage_amount=200, budget_limit=100)
        engine.add_record(name="b", service="s1", usage_amount=150, budget_limit=100)
        violations = engine.detect_budget_violations()
        assert len(violations) == 1
        assert violations[0]["severity"] == "critical"

    def test_detect_budget_no_violations(self, engine):
        engine.add_record(name="a", service="s1", usage_amount=50, budget_limit=100)
        assert len(engine.detect_budget_violations()) == 0

    def test_recommend_budget_adjustments_increase(self, engine):
        engine.add_record(name="a", service="s1", usage_amount=95, budget_limit=100)
        recs = engine.recommend_budget_adjustments()
        assert len(recs) == 1
        assert recs[0]["action"] == "increase_budget"

    def test_recommend_budget_adjustments_decrease(self, engine):
        engine.add_record(name="a", service="s1", usage_amount=10, budget_limit=100)
        recs = engine.recommend_budget_adjustments()
        assert len(recs) == 1
        assert recs[0]["action"] == "decrease_budget"

    def test_identify_gaps(self, engine):
        engine.add_record(name="low", score=10)
        assert len(engine.identify_gaps()) == 1

    def test_process_found(self, engine):
        engine.add_record(name="k1", score=70)
        assert engine.process("k1")["status"] == "processed"

    def test_process_not_found(self, engine):
        assert engine.process("x")["status"] == "not_found"

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=20)
        report = engine.generate_report()
        assert isinstance(report, AgentResourceGovernorReport)

    def test_clear_data(self, engine):
        engine.add_record(name="a")
        engine.clear_data()
        assert len(engine._records) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1


# ========== InvestigationPatternEngine ==========


class TestInvestigationPatternEnums:
    def test_pattern_type_values(self):
        assert PatternType.SYMPTOM_CLUSTER == "symptom_cluster"
        assert PatternType.ROOT_CAUSE_SIGNATURE == "root_cause_signature"
        assert PatternType.RESOLUTION_TEMPLATE == "resolution_template"

    def test_pattern_confidence_values(self):
        assert PatternConfidence.VALIDATED == "validated"
        assert PatternConfidence.EMERGING == "emerging"
        assert PatternConfidence.SPECULATIVE == "speculative"

    def test_match_quality_values(self):
        assert MatchQuality.EXACT == "exact"
        assert MatchQuality.SIMILAR == "similar"
        assert MatchQuality.PARTIAL == "partial"


class TestInvestigationPatternModels:
    def test_record_defaults(self):
        r = InvestigationPatternRecord()
        assert r.pattern_type == PatternType.SYMPTOM_CLUSTER
        assert r.match_count == 0

    def test_analysis_defaults(self):
        a = InvestigationPatternAnalysis()
        assert a.breached is False

    def test_report_defaults(self):
        r = InvestigationPatternReport()
        assert r.by_pattern_type == {}


class TestInvestigationPatternEngine:
    @pytest.fixture()
    def engine(self):
        return InvestigationPatternEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._max_records == 100

    def test_add_record(self, engine):
        r = engine.add_record(name="pattern-1", service="svc-a", score=70)
        assert r.name == "pattern-1"

    def test_get_record(self, engine):
        r = engine.add_record(name="test")
        assert engine.get_record(r.id) is not None

    def test_get_record_not_found(self, engine):
        assert engine.get_record("nope") is None

    def test_list_records_filter_type(self, engine):
        engine.add_record(name="a", pattern_type=PatternType.SYMPTOM_CLUSTER)
        engine.add_record(name="b", pattern_type=PatternType.ROOT_CAUSE_SIGNATURE)
        results = engine.list_records(pattern_type=PatternType.SYMPTOM_CLUSTER)
        assert len(results) == 1

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r-{i}")
        assert len(engine._records) == 100

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="a1")
        assert a.name == "a1"

    def test_extract_investigation_patterns(self, engine):
        engine.add_record(name="p1", pattern_hash="hash-1", service="s1", score=80)
        engine.add_record(name="p1", pattern_hash="hash-1", service="s2", score=70)
        engine.add_record(name="p2", pattern_hash="hash-2", service="s1", score=60)
        patterns = engine.extract_investigation_patterns()
        assert len(patterns) == 1  # only hash-1 has >= 2 occurrences
        assert patterns[0]["occurrences"] == 2

    def test_extract_patterns_none(self, engine):
        engine.add_record(name="p1", pattern_hash="h1", score=80)
        patterns = engine.extract_investigation_patterns()
        assert len(patterns) == 0

    def test_match_incident_to_pattern(self, engine):
        engine.add_record(
            name="validated",
            pattern_confidence=PatternConfidence.VALIDATED,
            pattern_hash="h1",
            service="s1",
        )
        engine.add_record(
            name="incident",
            pattern_confidence=PatternConfidence.EMERGING,
            pattern_hash="h1",
            service="s1",
        )
        matches = engine.match_incident_to_pattern()
        assert len(matches) == 1
        assert matches[0]["pattern_name"] == "validated"

    def test_match_incident_no_match(self, engine):
        engine.add_record(
            name="a", pattern_confidence=PatternConfidence.VALIDATED, pattern_hash="h1"
        )
        engine.add_record(
            name="b", pattern_confidence=PatternConfidence.EMERGING, pattern_hash="h2"
        )
        matches = engine.match_incident_to_pattern()
        assert len(matches) == 0

    def test_compute_pattern_accuracy(self, engine):
        engine.add_record(
            name="a",
            pattern_type=PatternType.SYMPTOM_CLUSTER,
            match_quality=MatchQuality.EXACT,
            score=90,
        )
        engine.add_record(
            name="b",
            pattern_type=PatternType.SYMPTOM_CLUSTER,
            match_quality=MatchQuality.PARTIAL,
            score=50,
        )
        results = engine.compute_pattern_accuracy()
        assert len(results) == 1
        assert results[0]["accuracy_pct"] == 50.0

    def test_identify_gaps(self, engine):
        engine.add_record(name="low", score=10)
        assert len(engine.identify_gaps()) == 1

    def test_process_found(self, engine):
        engine.add_record(name="k1", score=70)
        assert engine.process("k1")["status"] == "processed"

    def test_process_not_found(self, engine):
        assert engine.process("x")["status"] == "not_found"

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=20)
        report = engine.generate_report()
        assert isinstance(report, InvestigationPatternReport)

    def test_generate_report_healthy(self, engine):
        engine.add_record(name="a", score=90)
        report = engine.generate_report()
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self, engine):
        engine.add_record(name="a")
        engine.clear_data()
        assert len(engine._records) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1

    def test_analyze_distribution(self, engine):
        engine.add_record(name="a", pattern_type=PatternType.SYMPTOM_CLUSTER, score=80)
        dist = engine.analyze_distribution()
        assert "symptom_cluster" in dist

    def test_rank_by_score(self, engine):
        engine.add_record(name="a", service="s1", score=20)
        engine.add_record(name="b", service="s2", score=80)
        ranked = engine.rank_by_score()
        assert ranked[0]["service"] == "s1"


# ========== AgentEvolutionTrackerEngine ==========


class TestEvolutionTrackerEnums:
    def test_evolution_phase_values(self):
        assert EvolutionPhase.BOOTSTRAP == "bootstrap"
        assert EvolutionPhase.LEARNING == "learning"
        assert EvolutionPhase.PROFICIENT == "proficient"
        assert EvolutionPhase.EXPERT == "expert"
        assert EvolutionPhase.PLATEAU == "plateau"

    def test_capability_domain_values(self):
        assert CapabilityDomain.INVESTIGATION == "investigation"
        assert CapabilityDomain.REMEDIATION == "remediation"
        assert CapabilityDomain.SECURITY == "security"
        assert CapabilityDomain.OPTIMIZATION == "optimization"

    def test_evolution_trend_values(self):
        assert EvolutionTrend.ACCELERATING == "accelerating"
        assert EvolutionTrend.STEADY == "steady"
        assert EvolutionTrend.DECELERATING == "decelerating"
        assert EvolutionTrend.REGRESSING == "regressing"


class TestEvolutionTrackerModels:
    def test_record_defaults(self):
        r = AgentEvolutionTrackerRecord()
        assert r.evolution_phase == EvolutionPhase.BOOTSTRAP
        assert r.skill_count == 0

    def test_analysis_defaults(self):
        a = AgentEvolutionTrackerAnalysis()
        assert a.breached is False

    def test_report_defaults(self):
        r = AgentEvolutionTrackerReport()
        assert r.by_evolution_phase == {}


class TestEvolutionTrackerEngine:
    @pytest.fixture()
    def engine(self):
        return AgentEvolutionTrackerEngine(max_records=100, threshold=50.0)

    def test_init(self, engine):
        assert engine._max_records == 100

    def test_add_record(self, engine):
        r = engine.add_record(name="agent-1", service="svc-a", score=80)
        assert r.name == "agent-1"

    def test_get_record(self, engine):
        r = engine.add_record(name="test")
        assert engine.get_record(r.id) is not None

    def test_get_record_not_found(self, engine):
        assert engine.get_record("nope") is None

    def test_list_records_filter_phase(self, engine):
        engine.add_record(name="a", evolution_phase=EvolutionPhase.BOOTSTRAP)
        engine.add_record(name="b", evolution_phase=EvolutionPhase.EXPERT)
        results = engine.list_records(evolution_phase=EvolutionPhase.EXPERT)
        assert len(results) == 1

    def test_list_records_filter_domain(self, engine):
        engine.add_record(name="a", capability_domain=CapabilityDomain.SECURITY)
        engine.add_record(name="b", capability_domain=CapabilityDomain.INVESTIGATION)
        results = engine.list_records(capability_domain=CapabilityDomain.SECURITY)
        assert len(results) == 1

    def test_ring_buffer(self, engine):
        for i in range(150):
            engine.add_record(name=f"r-{i}")
        assert len(engine._records) == 100

    def test_add_analysis(self, engine):
        a = engine.add_analysis(name="a1")
        assert a.name == "a1"

    def test_track_capability_growth(self, engine):
        engine.add_record(
            name="agent-a",
            evolution_phase=EvolutionPhase.LEARNING,
            capability_domain=CapabilityDomain.INVESTIGATION,
            score=60,
            skill_count=5,
            version="1.0",
        )
        engine.add_record(
            name="agent-a",
            evolution_phase=EvolutionPhase.PROFICIENT,
            capability_domain=CapabilityDomain.SECURITY,
            score=80,
            skill_count=10,
            version="2.0",
        )
        results = engine.track_capability_growth()
        assert len(results) == 1
        assert results[0]["phase_depth"] == 3  # proficient is index 2, +1

    def test_detect_performance_plateaus(self, engine):
        engine.add_record(name="agent-a", evolution_phase=EvolutionPhase.PLATEAU, score=40)
        engine.add_record(name="agent-a", evolution_phase=EvolutionPhase.PROFICIENT, score=80)
        plateaus = engine.detect_performance_plateaus()
        assert len(plateaus) == 1
        assert plateaus[0]["plateau_count"] == 1

    def test_detect_plateaus_none(self, engine):
        engine.add_record(
            name="agent-a",
            evolution_phase=EvolutionPhase.LEARNING,
            evolution_trend=EvolutionTrend.ACCELERATING,
            score=80,
        )
        plateaus = engine.detect_performance_plateaus()
        assert len(plateaus) == 0

    def test_recommend_evolution_path_regression(self, engine):
        engine.add_record(
            name="agent-a",
            evolution_phase=EvolutionPhase.PROFICIENT,
            evolution_trend=EvolutionTrend.REGRESSING,
            capability_domain=CapabilityDomain.SECURITY,
            score=40,
        )
        recs = engine.recommend_evolution_path()
        assert len(recs) == 1
        assert recs[0]["issue"] == "regression_detected"
        assert recs[0]["priority"] == "high"

    def test_recommend_evolution_path_plateau(self, engine):
        engine.add_record(
            name="agent-a",
            evolution_phase=EvolutionPhase.PLATEAU,
            evolution_trend=EvolutionTrend.STEADY,
            score=70,
        )
        recs = engine.recommend_evolution_path()
        assert len(recs) == 1
        assert recs[0]["issue"] == "plateau"

    def test_recommend_evolution_path_growth(self, engine):
        engine.add_record(
            name="agent-a",
            evolution_phase=EvolutionPhase.BOOTSTRAP,
            evolution_trend=EvolutionTrend.ACCELERATING,
            score=60,
        )
        recs = engine.recommend_evolution_path()
        assert len(recs) == 1
        assert recs[0]["issue"] == "growth_opportunity"

    def test_identify_gaps(self, engine):
        engine.add_record(name="low", score=10)
        assert len(engine.identify_gaps()) == 1

    def test_process_found(self, engine):
        engine.add_record(name="k1", score=70)
        assert engine.process("k1")["status"] == "processed"

    def test_process_not_found(self, engine):
        assert engine.process("x")["status"] == "not_found"

    def test_generate_report(self, engine):
        engine.add_record(name="a", score=20)
        report = engine.generate_report()
        assert isinstance(report, AgentEvolutionTrackerReport)

    def test_generate_report_healthy(self, engine):
        engine.add_record(name="a", score=90)
        report = engine.generate_report()
        assert "healthy" in report.recommendations[0]

    def test_clear_data(self, engine):
        engine.add_record(name="a")
        engine.clear_data()
        assert len(engine._records) == 0

    def test_get_stats(self, engine):
        engine.add_record(name="a", service="s1", team="t1")
        stats = engine.get_stats()
        assert stats["total_records"] == 1

    def test_analyze_distribution(self, engine):
        engine.add_record(name="a", evolution_phase=EvolutionPhase.LEARNING, score=80)
        dist = engine.analyze_distribution()
        assert "learning" in dist

    def test_rank_by_score(self, engine):
        engine.add_record(name="a", service="s1", score=20)
        engine.add_record(name="b", service="s2", score=80)
        ranked = engine.rank_by_score()
        assert ranked[0]["service"] == "s1"
