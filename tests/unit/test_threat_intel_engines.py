"""Tests for threat intel security engines:
SoarPlaybookAnalyticsEngine, IdentityRiskEngine, IOCLifecycleEngine, ThreatFeedQualityEngine.
"""

from __future__ import annotations

import pytest

from shieldops.security.identity_risk_engine import (
    EntityType,
    IdentityRiskEngine,
    IdentityRiskRecord,
    IdentityRiskReport,
    RiskAction,
    RiskFactor,
    RiskSignal,
)
from shieldops.security.ioc_lifecycle_engine import (
    IOCAction,
    IOCLifecycleAnalysis,
    IOCLifecycleEngine,
    IOCLifecycleRecord,
    IOCLifecycleReport,
    IOCPhase,
    IOCType,
)
from shieldops.security.soar_playbook_analytics_engine import (
    AutomationLevel,
    PlaybookOutcome,
    PlaybookTier,
    SoarPlaybookAnalyticsAnalysis,
    SoarPlaybookAnalyticsEngine,
    SoarPlaybookAnalyticsRecord,
    SoarPlaybookAnalyticsReport,
)
from shieldops.security.threat_feed_quality_engine import (
    FeedQualityMetric,
    FeedTier,
    QualityTrend,
    ThreatFeedAnalysis,
    ThreatFeedQualityEngine,
    ThreatFeedRecord,
    ThreatFeedReport,
)

# ============================================================
# SOAR Playbook Analytics Engine
# ============================================================


class TestSoarPlaybookAnalyticsEnums:
    def test_playbook_outcome_values(self) -> None:
        assert PlaybookOutcome.SUCCESS == "success"
        assert PlaybookOutcome.PARTIAL == "partial"
        assert PlaybookOutcome.FAILURE == "failure"
        assert PlaybookOutcome.TIMEOUT == "timeout"

    def test_automation_level_values(self) -> None:
        assert AutomationLevel.FULL == "full"
        assert AutomationLevel.SEMI == "semi"
        assert AutomationLevel.MANUAL == "manual"

    def test_playbook_tier_values(self) -> None:
        assert PlaybookTier.CRITICAL == "critical"
        assert PlaybookTier.STANDARD == "standard"
        assert PlaybookTier.LOW == "low"


class TestSoarPlaybookAnalyticsModels:
    def test_record_defaults(self) -> None:
        r = SoarPlaybookAnalyticsRecord()
        assert r.id
        assert r.playbook_name == ""
        assert r.incident_type == ""
        assert r.playbook_outcome == PlaybookOutcome.FAILURE
        assert r.automation_level == AutomationLevel.MANUAL
        assert r.playbook_tier == PlaybookTier.STANDARD
        assert r.execution_time_seconds == 0.0
        assert r.response_time_seconds == 0.0
        assert r.step_count == 0
        assert r.automated_steps == 0
        assert r.manual_steps == 0
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = SoarPlaybookAnalyticsAnalysis()
        assert a.id
        assert a.performance_score == 0.0
        assert a.automation_potential == 0.0
        assert a.playbook_outcome == PlaybookOutcome.FAILURE
        assert a.created_at > 0

    def test_report_defaults(self) -> None:
        rpt = SoarPlaybookAnalyticsReport()
        assert rpt.total_records == 0
        assert rpt.total_analyses == 0
        assert rpt.avg_execution_time == 0.0
        assert rpt.by_playbook_outcome == {}
        assert rpt.by_automation_level == {}
        assert rpt.by_playbook_tier == {}
        assert rpt.underperforming_playbooks == []
        assert rpt.recommendations == []
        assert rpt.generated_at > 0


class TestSoarPlaybookAnalyticsEngine:
    @pytest.fixture()
    def engine(self) -> SoarPlaybookAnalyticsEngine:
        return SoarPlaybookAnalyticsEngine(max_records=100)

    def test_add_record(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        rec = engine.add_record(
            playbook_name="phishing-response",
            incident_type="phishing",
            playbook_outcome=PlaybookOutcome.SUCCESS,
            automation_level=AutomationLevel.FULL,
            playbook_tier=PlaybookTier.CRITICAL,
            execution_time_seconds=120.0,
            response_time_seconds=30.0,
            step_count=10,
            automated_steps=8,
            manual_steps=2,
        )
        assert isinstance(rec, SoarPlaybookAnalyticsRecord)
        assert rec.playbook_name == "phishing-response"
        assert rec.playbook_outcome == PlaybookOutcome.SUCCESS
        assert rec.execution_time_seconds == 120.0

    def test_add_record_defaults(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        rec = engine.add_record()
        assert rec.playbook_name == ""
        assert rec.playbook_outcome == PlaybookOutcome.FAILURE
        assert rec.automation_level == AutomationLevel.MANUAL

    def test_process_found_success(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        rec = engine.add_record(
            playbook_name="malware-cleanup",
            playbook_outcome=PlaybookOutcome.SUCCESS,
            step_count=5,
            manual_steps=3,
        )
        result = engine.process(rec.id)
        assert isinstance(result, SoarPlaybookAnalyticsAnalysis)
        assert result.performance_score == 1.0
        assert result.automation_potential == 0.6  # 3/5

    def test_process_found_partial(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        rec = engine.add_record(
            playbook_name="partial-pb",
            playbook_outcome=PlaybookOutcome.PARTIAL,
            step_count=4,
            manual_steps=2,
        )
        result = engine.process(rec.id)
        assert isinstance(result, SoarPlaybookAnalyticsAnalysis)
        assert result.performance_score == 0.6

    def test_process_found_timeout(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        rec = engine.add_record(
            playbook_name="timeout-pb",
            playbook_outcome=PlaybookOutcome.TIMEOUT,
            step_count=0,
        )
        result = engine.process(rec.id)
        assert isinstance(result, SoarPlaybookAnalyticsAnalysis)
        assert result.performance_score == 0.1
        assert result.automation_potential == 0.0  # step_count=0

    def test_process_not_found(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        result = engine.process("nonexistent")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"
        assert result["key"] == "nonexistent"

    def test_generate_report_populated(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        engine.add_record(
            playbook_name="pb1",
            playbook_outcome=PlaybookOutcome.SUCCESS,
            automation_level=AutomationLevel.FULL,
            playbook_tier=PlaybookTier.CRITICAL,
            execution_time_seconds=60.0,
        )
        engine.add_record(
            playbook_name="pb2",
            playbook_outcome=PlaybookOutcome.FAILURE,
            automation_level=AutomationLevel.MANUAL,
            playbook_tier=PlaybookTier.LOW,
            execution_time_seconds=120.0,
        )
        report = engine.generate_report()
        assert isinstance(report, SoarPlaybookAnalyticsReport)
        assert report.total_records == 2
        assert report.avg_execution_time == 90.0
        assert "success" in report.by_playbook_outcome
        assert "failure" in report.by_playbook_outcome
        assert "full" in report.by_automation_level
        assert "pb2" in report.underperforming_playbooks
        assert len(report.recommendations) >= 1

    def test_generate_report_empty(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        report = engine.generate_report()
        assert report.total_records == 0
        assert report.avg_execution_time == 0.0
        assert report.by_playbook_outcome == {}

    def test_generate_report_normal_recommendation(
        self, engine: SoarPlaybookAnalyticsEngine
    ) -> None:
        engine.add_record(
            playbook_name="good-pb",
            playbook_outcome=PlaybookOutcome.SUCCESS,
            execution_time_seconds=10.0,
        )
        report = engine.generate_report()
        assert any("normal parameters" in r for r in report.recommendations)

    def test_get_stats(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        engine.add_record(playbook_outcome=PlaybookOutcome.PARTIAL)
        stats = engine.get_stats()
        assert stats["total_records"] == 1
        assert stats["total_analyses"] == 0
        assert "partial" in stats["playbook_outcome_distribution"]

    def test_clear_data(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        engine.add_record()
        rec = engine._records[0]
        engine.process(rec.id)
        result = engine.clear_data()
        assert result == {"status": "cleared"}
        assert engine.get_stats()["total_records"] == 0
        assert engine.get_stats()["total_analyses"] == 0

    def test_ring_buffer_eviction(self) -> None:
        engine = SoarPlaybookAnalyticsEngine(max_records=3)
        for i in range(5):
            engine.add_record(playbook_name=f"pb-{i}")
        assert engine.get_stats()["total_records"] == 3
        # oldest records evicted, newest kept
        names = [r.playbook_name for r in engine._records]
        assert "pb-2" in names
        assert "pb-4" in names
        assert "pb-0" not in names

    def test_rank_playbooks_by_performance(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        engine.add_record(
            playbook_name="good",
            playbook_outcome=PlaybookOutcome.SUCCESS,
            execution_time_seconds=30.0,
        )
        engine.add_record(
            playbook_name="bad",
            playbook_outcome=PlaybookOutcome.FAILURE,
            execution_time_seconds=300.0,
        )
        ranked = engine.rank_playbooks_by_performance()
        assert len(ranked) == 2
        assert ranked[0]["playbook_name"] == "good"
        assert ranked[0]["success_rate"] == 1.0
        assert ranked[0]["rank_tier"] == "top"
        assert ranked[1]["success_rate"] == 0.0
        assert ranked[1]["rank_tier"] == "low"

    def test_rank_playbooks_by_performance_empty(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        assert engine.rank_playbooks_by_performance() == []

    def test_identify_automation_candidates(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        engine.add_record(
            playbook_name="manual-heavy",
            automation_level=AutomationLevel.MANUAL,
            step_count=10,
            manual_steps=8,
        )
        candidates = engine.identify_automation_candidates()
        assert len(candidates) == 1
        assert candidates[0]["automation_potential"] == 0.8
        assert candidates[0]["priority"] == "high"

    def test_identify_automation_candidates_skips_full(
        self, engine: SoarPlaybookAnalyticsEngine
    ) -> None:
        engine.add_record(
            playbook_name="auto-pb",
            automation_level=AutomationLevel.FULL,
            step_count=10,
            manual_steps=0,
        )
        candidates = engine.identify_automation_candidates()
        assert len(candidates) == 0

    def test_identify_automation_candidates_empty(
        self, engine: SoarPlaybookAnalyticsEngine
    ) -> None:
        assert engine.identify_automation_candidates() == []

    def test_calculate_mean_time_to_respond(self, engine: SoarPlaybookAnalyticsEngine) -> None:
        engine.add_record(
            playbook_name="pb1",
            incident_type="malware",
            response_time_seconds=60.0,
            execution_time_seconds=120.0,
        )
        mttr = engine.calculate_mean_time_to_respond()
        assert len(mttr) == 1
        assert mttr[0]["incident_type"] == "malware"
        assert mttr[0]["mean_time_to_respond"] == 180.0
        assert mttr[0]["rating"] == "excellent"

    def test_calculate_mean_time_to_respond_rating_good(
        self, engine: SoarPlaybookAnalyticsEngine
    ) -> None:
        engine.add_record(
            incident_type="ddos",
            response_time_seconds=200.0,
            execution_time_seconds=400.0,
        )
        mttr = engine.calculate_mean_time_to_respond()
        assert mttr[0]["rating"] == "good"

    def test_calculate_mean_time_to_respond_empty(
        self, engine: SoarPlaybookAnalyticsEngine
    ) -> None:
        assert engine.calculate_mean_time_to_respond() == []


# ============================================================
# Identity Risk Engine
# ============================================================


class TestIdentityRiskEnums:
    def test_risk_factor_values(self) -> None:
        assert RiskFactor.EXCESSIVE_PERMISSIONS == "excessive_permissions"
        assert RiskFactor.NO_MFA == "no_mfa"
        assert RiskFactor.STALE_CREDENTIALS == "stale_credentials"
        assert RiskFactor.IMPOSSIBLE_TRAVEL == "impossible_travel"
        assert RiskFactor.PRIVILEGE_ESCALATION == "privilege_escalation"
        assert RiskFactor.LATERAL_MOVEMENT == "lateral_movement"

    def test_entity_type_values(self) -> None:
        assert EntityType.HUMAN == "human"
        assert EntityType.SERVICE_ACCOUNT == "service_account"
        assert EntityType.AI_AGENT == "ai_agent"
        assert EntityType.FEDERATED_IDENTITY == "federated_identity"
        assert EntityType.GUEST == "guest"
        assert EntityType.EXTERNAL_CONTRACTOR == "external_contractor"

    def test_risk_action_values(self) -> None:
        assert RiskAction.MONITOR == "monitor"
        assert RiskAction.RESTRICT == "restrict"
        assert RiskAction.REQUIRE_MFA == "require_mfa"
        assert RiskAction.REVOKE == "revoke"
        assert RiskAction.QUARANTINE == "quarantine"
        assert RiskAction.ESCALATE == "escalate"


class TestIdentityRiskModels:
    def test_record_defaults(self) -> None:
        r = IdentityRiskRecord()
        assert r.id
        assert r.identity_id == ""
        assert r.identity_name == ""
        assert r.entity_type == EntityType.HUMAN
        assert r.risk_factors == []
        assert r.composite_risk_score == 0.0
        assert r.recommended_action == RiskAction.MONITOR
        assert r.details == ""
        assert r.created_at > 0

    def test_signal_defaults(self) -> None:
        s = RiskSignal()
        assert s.id
        assert s.identity_id == ""
        assert s.risk_factor == RiskFactor.EXCESSIVE_PERMISSIONS
        assert s.severity == 0.0
        assert s.evidence == ""
        assert s.source == ""
        assert s.detected_at > 0

    def test_report_defaults(self) -> None:
        rpt = IdentityRiskReport()
        assert rpt.total_identities == 0
        assert rpt.total_signals == 0
        assert rpt.high_risk_count == 0
        assert rpt.by_entity_type == {}
        assert rpt.by_risk_factor == {}
        assert rpt.action_recommendations == {}
        assert rpt.recommendations == []
        assert rpt.generated_at > 0


class TestIdentityRiskEngine:
    @pytest.fixture()
    def engine(self) -> IdentityRiskEngine:
        return IdentityRiskEngine(max_records=100)

    def test_add_risk_signal(self, engine: IdentityRiskEngine) -> None:
        signal = engine.add_risk_signal(
            identity_id="user-1",
            risk_factor=RiskFactor.EXCESSIVE_PERMISSIONS,
            severity=80.0,
            evidence="Over-privileged account",
            source="iam-scanner",
        )
        assert isinstance(signal, RiskSignal)
        assert signal.identity_id == "user-1"
        assert signal.severity == 80.0
        assert signal.source == "iam-scanner"

    def test_add_risk_signal_defaults(self, engine: IdentityRiskEngine) -> None:
        signal = engine.add_risk_signal(identity_id="default-user")
        assert signal.risk_factor == RiskFactor.EXCESSIVE_PERMISSIONS
        assert signal.severity == 0.0
        assert signal.evidence == ""

    def test_calculate_composite_risk_high(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(
            identity_id="svc-1",
            risk_factor=RiskFactor.PRIVILEGE_ESCALATION,
            severity=90.0,
        )
        result = engine.calculate_composite_risk("svc-1")
        assert isinstance(result, IdentityRiskRecord)
        # weight for PRIVILEGE_ESCALATION = 35.0; score = 35.0 * (90/100) = 31.5
        assert result.composite_risk_score == 31.5
        assert result.recommended_action == RiskAction.REQUIRE_MFA

    def test_calculate_composite_risk_low(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(
            identity_id="safe-user",
            risk_factor=RiskFactor.STALE_CREDENTIALS,
            severity=10.0,
        )
        result = engine.calculate_composite_risk("safe-user")
        assert isinstance(result, IdentityRiskRecord)
        # weight for STALE_CREDENTIALS = 10.0; score = 10.0 * (10/100) = 1.0
        assert result.composite_risk_score == 1.0
        assert result.recommended_action == RiskAction.MONITOR

    def test_calculate_composite_risk_medium(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(
            identity_id="mid-user",
            risk_factor=RiskFactor.NO_MFA,
            severity=80.0,
        )
        engine.add_risk_signal(
            identity_id="mid-user",
            risk_factor=RiskFactor.STALE_CREDENTIALS,
            severity=50.0,
        )
        result = engine.calculate_composite_risk("mid-user")
        assert isinstance(result, IdentityRiskRecord)
        # NO_MFA: 25*0.8=20.0, STALE_CREDENTIALS: 10*0.5=5.0 => total=25.0
        assert result.composite_risk_score == 25.0
        assert result.recommended_action == RiskAction.REQUIRE_MFA

    def test_calculate_composite_risk_no_signals(self, engine: IdentityRiskEngine) -> None:
        result = engine.calculate_composite_risk("nonexistent")
        assert isinstance(result, IdentityRiskRecord)
        assert result.composite_risk_score == 0.0
        assert result.identity_id == "nonexistent"

    def test_generate_risk_report_populated(self, engine: IdentityRiskEngine) -> None:
        # u1 gets high composite: LATERAL_MOVEMENT(40*0.95=38) + PRIVILEGE_ESCALATION(35*0.9=31.5) = 69.5
        engine.add_risk_signal(
            identity_id="u1",
            risk_factor=RiskFactor.LATERAL_MOVEMENT,
            severity=95.0,
        )
        engine.add_risk_signal(
            identity_id="u1",
            risk_factor=RiskFactor.PRIVILEGE_ESCALATION,
            severity=90.0,
        )
        engine.add_risk_signal(
            identity_id="u2",
            risk_factor=RiskFactor.STALE_CREDENTIALS,
            severity=10.0,
        )
        engine.calculate_composite_risk("u1")
        engine.calculate_composite_risk("u2")
        report = engine.generate_risk_report()
        assert isinstance(report, IdentityRiskReport)
        assert report.total_identities == 2
        assert report.total_signals == 3
        assert report.high_risk_count >= 1
        assert len(report.by_risk_factor) >= 1
        assert len(report.recommendations) >= 1

    def test_generate_risk_report_empty(self, engine: IdentityRiskEngine) -> None:
        report = engine.generate_risk_report()
        assert report.total_identities == 0
        assert report.total_signals == 0

    def test_generate_risk_report_meets_targets(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(
            identity_id="safe",
            risk_factor=RiskFactor.STALE_CREDENTIALS,
            severity=5.0,
        )
        engine.calculate_composite_risk("safe")
        report = engine.generate_risk_report()
        assert any("meets targets" in r.lower() for r in report.recommendations)

    def test_get_stats(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(
            identity_id="test-id",
            risk_factor=RiskFactor.NO_MFA,
            severity=50.0,
        )
        stats = engine.get_stats()
        assert stats["total_signals"] == 1
        assert stats["total_records"] == 0
        assert "no_mfa" in stats["risk_factor_distribution"]

    def test_clear_data(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(identity_id="clear-me", severity=50.0)
        engine.calculate_composite_risk("clear-me")
        result = engine.clear_data()
        assert result == {"status": "cleared"}
        assert engine.get_stats()["total_records"] == 0
        assert engine.get_stats()["total_signals"] == 0

    def test_ring_buffer_eviction(self) -> None:
        engine = IdentityRiskEngine(max_records=3)
        for i in range(5):
            engine.add_risk_signal(identity_id=f"id-{i}", severity=float(i * 10))
        assert engine.get_stats()["total_signals"] == 3
        ids = [s.identity_id for s in engine._signals]
        assert "id-0" not in ids
        assert "id-4" in ids

    def test_calculate_composite_risk_multiple_signals(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(
            identity_id="user-x",
            risk_factor=RiskFactor.NO_MFA,
            severity=60.0,
        )
        engine.add_risk_signal(
            identity_id="user-x",
            risk_factor=RiskFactor.IMPOSSIBLE_TRAVEL,
            severity=90.0,
        )
        result = engine.calculate_composite_risk("user-x")
        assert result.identity_id == "user-x"
        # NO_MFA: 25*0.6=15.0, IMPOSSIBLE_TRAVEL: 30*0.9=27.0 => total=42.0
        assert result.composite_risk_score == 42.0
        assert len(result.risk_factors) == 2
        assert result.recommended_action == RiskAction.RESTRICT

    def test_calculate_composite_risk_no_data(self, engine: IdentityRiskEngine) -> None:
        result = engine.calculate_composite_risk("unknown")
        assert result.composite_risk_score == 0.0
        assert result.identity_id == "unknown"

    def test_detect_anomalous_access(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(
            identity_id="u1",
            risk_factor=RiskFactor.IMPOSSIBLE_TRAVEL,
            severity=70.0,
            evidence="Login from Tokyo",
        )
        engine.add_risk_signal(
            identity_id="u1",
            risk_factor=RiskFactor.STALE_CREDENTIALS,
            severity=10.0,
        )
        results = engine.detect_anomalous_access()
        assert len(results) == 1
        assert results[0]["identity_id"] == "u1"
        assert results[0]["anomalous_signals"] == 1
        assert "impossible_travel" in results[0]["factors"]
        assert results[0]["max_severity"] == 70.0

    def test_detect_anomalous_access_lateral_movement(self, engine: IdentityRiskEngine) -> None:
        for _ in range(3):
            engine.add_risk_signal(
                identity_id="bad-user",
                risk_factor=RiskFactor.LATERAL_MOVEMENT,
                severity=85.0,
            )
        results = engine.detect_anomalous_access()
        assert len(results) == 1
        assert results[0]["anomalous_signals"] == 3
        assert results[0]["max_severity"] == 85.0

    def test_detect_anomalous_access_empty(self, engine: IdentityRiskEngine) -> None:
        assert engine.detect_anomalous_access() == []

    def test_recommend_actions(self, engine: IdentityRiskEngine) -> None:
        # Need score > 20 to get non-MONITOR action: NO_MFA(25*0.8=20) + EXCESSIVE(15*0.8=12) = 32
        engine.add_risk_signal(
            identity_id="svc-1",
            risk_factor=RiskFactor.NO_MFA,
            severity=80.0,
        )
        engine.add_risk_signal(
            identity_id="svc-1",
            risk_factor=RiskFactor.EXCESSIVE_PERMISSIONS,
            severity=80.0,
        )
        engine.calculate_composite_risk("svc-1")
        results = engine.recommend_actions()
        assert len(results) >= 1
        assert results[0]["identity_id"] == "svc-1"
        assert results[0]["recommended_action"] in [a.value for a in RiskAction]

    def test_recommend_actions_high_risk(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(
            identity_id="risky",
            risk_factor=RiskFactor.PRIVILEGE_ESCALATION,
            severity=95.0,
        )
        engine.add_risk_signal(
            identity_id="risky",
            risk_factor=RiskFactor.LATERAL_MOVEMENT,
            severity=90.0,
        )
        engine.calculate_composite_risk("risky")
        results = engine.recommend_actions()
        assert len(results) >= 1
        assert results[0]["risk_score"] > 0

    def test_recommend_actions_priv_escalation(self, engine: IdentityRiskEngine) -> None:
        engine.add_risk_signal(
            identity_id="escalator",
            risk_factor=RiskFactor.PRIVILEGE_ESCALATION,
            severity=70.0,
        )
        engine.calculate_composite_risk("escalator")
        results = engine.recommend_actions()
        assert len(results) >= 1
        assert "privilege_escalation" in results[0]["risk_factors"]

    def test_recommend_actions_empty(self, engine: IdentityRiskEngine) -> None:
        assert engine.recommend_actions() == []


# ============================================================
# IOC Lifecycle Engine
# ============================================================


class TestIOCLifecycleEnums:
    def test_ioc_phase_values(self) -> None:
        assert IOCPhase.DISCOVERED == "discovered"
        assert IOCPhase.VALIDATED == "validated"
        assert IOCPhase.DEPLOYED == "deployed"
        assert IOCPhase.ACTIVE == "active"
        assert IOCPhase.EXPIRED == "expired"
        assert IOCPhase.REVOKED == "revoked"

    def test_ioc_type_values(self) -> None:
        assert IOCType.IP_ADDRESS == "ip_address"
        assert IOCType.DOMAIN == "domain"
        assert IOCType.FILE_HASH == "file_hash"
        assert IOCType.URL == "url"
        assert IOCType.EMAIL_ADDRESS == "email_address"
        assert IOCType.CVE_ID == "cve_id"

    def test_ioc_action_values(self) -> None:
        assert IOCAction.BLOCK == "block"
        assert IOCAction.MONITOR == "monitor"
        assert IOCAction.ALERT == "alert"
        assert IOCAction.INVESTIGATE == "investigate"
        assert IOCAction.IGNORE == "ignore"


class TestIOCLifecycleModels:
    def test_record_defaults(self) -> None:
        r = IOCLifecycleRecord()
        assert r.id
        assert r.ioc_value == ""
        assert r.ioc_phase == IOCPhase.DISCOVERED
        assert r.ioc_type == IOCType.IP_ADDRESS
        assert r.ioc_action == IOCAction.MONITOR
        assert r.confidence == 0.0
        assert r.ttl_seconds == 86400.0
        assert r.source == ""
        assert r.detections == 0
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = IOCLifecycleAnalysis()
        assert a.id
        assert a.ioc_value == ""
        assert a.ioc_phase == IOCPhase.DISCOVERED
        assert a.ioc_type == IOCType.IP_ADDRESS
        assert a.recommended_action == ""
        assert a.risk_assessment == 0.0
        assert a.created_at > 0

    def test_report_defaults(self) -> None:
        rpt = IOCLifecycleReport()
        assert rpt.total_records == 0
        assert rpt.total_analyses == 0
        assert rpt.stale_count == 0
        assert rpt.avg_confidence == 0.0
        assert rpt.by_ioc_phase == {}
        assert rpt.by_ioc_type == {}
        assert rpt.by_ioc_action == {}
        assert rpt.top_stale == []
        assert rpt.recommendations == []
        assert rpt.generated_at > 0


class TestIOCLifecycleEngine:
    @pytest.fixture()
    def engine(self) -> IOCLifecycleEngine:
        return IOCLifecycleEngine(max_records=100)

    def test_add_record(self, engine: IOCLifecycleEngine) -> None:
        rec = engine.add_record(
            ioc_value="192.168.1.1",
            ioc_phase=IOCPhase.VALIDATED,
            ioc_type=IOCType.IP_ADDRESS,
            ioc_action=IOCAction.BLOCK,
            confidence=0.95,
            source="threat-feed-alpha",
            detections=10,
        )
        assert isinstance(rec, IOCLifecycleRecord)
        assert rec.ioc_value == "192.168.1.1"
        assert rec.confidence == 0.95
        assert rec.source == "threat-feed-alpha"

    def test_add_record_defaults(self, engine: IOCLifecycleEngine) -> None:
        rec = engine.add_record()
        assert rec.ioc_phase == IOCPhase.DISCOVERED
        assert rec.ioc_action == IOCAction.MONITOR
        assert rec.confidence == 0.0

    def test_process_found_high_confidence(self, engine: IOCLifecycleEngine) -> None:
        rec = engine.add_record(ioc_value="evil.com", confidence=0.9)
        result = engine.process(rec.id)
        assert isinstance(result, IOCLifecycleAnalysis)
        assert result.risk_assessment == 90.0
        assert "blocking" in result.recommended_action

    def test_process_found_medium_confidence(self, engine: IOCLifecycleEngine) -> None:
        rec = engine.add_record(ioc_value="suspect.com", confidence=0.6)
        result = engine.process(rec.id)
        assert isinstance(result, IOCLifecycleAnalysis)
        assert "Validate" in result.recommended_action

    def test_process_found_low_confidence(self, engine: IOCLifecycleEngine) -> None:
        rec = engine.add_record(ioc_value="maybe.com", confidence=0.3)
        result = engine.process(rec.id)
        assert isinstance(result, IOCLifecycleAnalysis)
        assert "Monitor" in result.recommended_action

    def test_process_not_found(self, engine: IOCLifecycleEngine) -> None:
        result = engine.process("nonexistent")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"
        assert result["key"] == "nonexistent"

    def test_generate_report_populated(self, engine: IOCLifecycleEngine) -> None:
        engine.add_record(
            ioc_value="1.2.3.4",
            ioc_phase=IOCPhase.ACTIVE,
            ioc_type=IOCType.IP_ADDRESS,
            confidence=0.8,
        )
        engine.add_record(
            ioc_value="bad.com",
            ioc_phase=IOCPhase.DISCOVERED,
            ioc_type=IOCType.DOMAIN,
            confidence=0.4,
        )
        report = engine.generate_report()
        assert isinstance(report, IOCLifecycleReport)
        assert report.total_records == 2
        assert report.avg_confidence == 0.6
        assert "active" in report.by_ioc_phase
        assert "discovered" in report.by_ioc_phase

    def test_generate_report_empty(self, engine: IOCLifecycleEngine) -> None:
        report = engine.generate_report()
        assert report.total_records == 0
        assert report.avg_confidence == 0.0
        assert report.by_ioc_phase == {}

    def test_get_stats(self, engine: IOCLifecycleEngine) -> None:
        engine.add_record(ioc_phase=IOCPhase.DEPLOYED)
        stats = engine.get_stats()
        assert stats["total_records"] == 1
        assert stats["total_analyses"] == 0
        assert "deployed" in stats["ioc_phase_distribution"]

    def test_clear_data(self, engine: IOCLifecycleEngine) -> None:
        engine.add_record()
        rec = engine._records[0]
        engine.process(rec.id)
        result = engine.clear_data()
        assert result == {"status": "cleared"}
        assert engine.get_stats()["total_records"] == 0
        assert engine.get_stats()["total_analyses"] == 0

    def test_ring_buffer_eviction(self) -> None:
        engine = IOCLifecycleEngine(max_records=3)
        for i in range(5):
            engine.add_record(ioc_value=f"ioc-{i}")
        assert engine.get_stats()["total_records"] == 3
        values = [r.ioc_value for r in engine._records]
        assert "ioc-0" not in values
        assert "ioc-4" in values

    def test_identify_stale_iocs(self, engine: IOCLifecycleEngine) -> None:
        engine.add_record(
            ioc_value="stale-ioc",
            ioc_phase=IOCPhase.ACTIVE,
            ttl_seconds=0.0,
        )
        stale = engine.identify_stale_iocs()
        assert len(stale) >= 1
        assert stale[0]["ioc_value"] == "stale-ioc"

    def test_identify_stale_iocs_skips_expired(self, engine: IOCLifecycleEngine) -> None:
        engine.add_record(
            ioc_value="already-expired",
            ioc_phase=IOCPhase.EXPIRED,
            ttl_seconds=0.0,
        )
        stale = engine.identify_stale_iocs()
        assert len(stale) == 0

    def test_identify_stale_iocs_skips_revoked(self, engine: IOCLifecycleEngine) -> None:
        engine.add_record(
            ioc_value="already-revoked",
            ioc_phase=IOCPhase.REVOKED,
            ttl_seconds=0.0,
        )
        stale = engine.identify_stale_iocs()
        assert len(stale) == 0

    def test_identify_stale_iocs_empty(self, engine: IOCLifecycleEngine) -> None:
        assert engine.identify_stale_iocs() == []

    def test_compute_ioc_effectiveness(self, engine: IOCLifecycleEngine) -> None:
        engine.add_record(ioc_value="ioc-1", detections=5)
        engine.add_record(ioc_value="ioc-2", detections=0)
        result = engine.compute_ioc_effectiveness()
        assert result["total_iocs"] == 2
        assert result["iocs_with_detections"] == 1
        assert result["effectiveness_rate"] == 50.0
        assert result["effectiveness_grade"] == "excellent"

    def test_compute_ioc_effectiveness_empty(self, engine: IOCLifecycleEngine) -> None:
        result = engine.compute_ioc_effectiveness()
        assert result["total_iocs"] == 0
        assert result["effectiveness_grade"] == "no_data"

    def test_recommend_ioc_actions_high_confidence(self, engine: IOCLifecycleEngine) -> None:
        engine.add_record(
            ioc_value="definite-bad",
            ioc_phase=IOCPhase.DISCOVERED,
            confidence=0.9,
        )
        results = engine.recommend_ioc_actions()
        assert len(results) == 1
        assert results[0]["recommended_action"] == "block"

    def test_recommend_ioc_actions_moderate(self, engine: IOCLifecycleEngine) -> None:
        engine.add_record(
            ioc_value="moderate",
            ioc_phase=IOCPhase.DISCOVERED,
            confidence=0.65,
        )
        results = engine.recommend_ioc_actions()
        assert results[0]["recommended_action"] == "alert"

    def test_recommend_ioc_actions_low(self, engine: IOCLifecycleEngine) -> None:
        engine.add_record(
            ioc_value="investigate-me",
            ioc_phase=IOCPhase.DISCOVERED,
            confidence=0.4,
        )
        results = engine.recommend_ioc_actions()
        assert results[0]["recommended_action"] == "investigate"

    def test_recommend_ioc_actions_very_low(self, engine: IOCLifecycleEngine) -> None:
        engine.add_record(
            ioc_value="noise",
            ioc_phase=IOCPhase.DISCOVERED,
            confidence=0.1,
        )
        results = engine.recommend_ioc_actions()
        assert results[0]["recommended_action"] == "ignore"

    def test_recommend_ioc_actions_skips_non_discovered(self, engine: IOCLifecycleEngine) -> None:
        engine.add_record(
            ioc_value="deployed-ioc",
            ioc_phase=IOCPhase.DEPLOYED,
            confidence=0.95,
        )
        results = engine.recommend_ioc_actions()
        assert len(results) == 0

    def test_recommend_ioc_actions_empty(self, engine: IOCLifecycleEngine) -> None:
        assert engine.recommend_ioc_actions() == []


# ============================================================
# Threat Feed Quality Engine
# ============================================================


class TestThreatFeedQualityEnums:
    def test_feed_quality_metric_values(self) -> None:
        assert FeedQualityMetric.FALSE_POSITIVE_RATE == "false_positive_rate"
        assert FeedQualityMetric.TIMELINESS == "timeliness"
        assert FeedQualityMetric.COVERAGE == "coverage"
        assert FeedQualityMetric.UNIQUENESS == "uniqueness"

    def test_feed_tier_values(self) -> None:
        assert FeedTier.PREMIUM == "premium"
        assert FeedTier.STANDARD == "standard"
        assert FeedTier.COMMUNITY == "community"
        assert FeedTier.INTERNAL == "internal"

    def test_quality_trend_values(self) -> None:
        assert QualityTrend.IMPROVING == "improving"
        assert QualityTrend.STABLE == "stable"
        assert QualityTrend.DEGRADING == "degrading"
        assert QualityTrend.UNRELIABLE == "unreliable"


class TestThreatFeedQualityModels:
    def test_record_defaults(self) -> None:
        r = ThreatFeedRecord()
        assert r.id
        assert r.feed_name == ""
        assert r.quality_metric == FeedQualityMetric.FALSE_POSITIVE_RATE
        assert r.feed_tier == FeedTier.STANDARD
        assert r.quality_trend == QualityTrend.STABLE
        assert r.quality_score == 0.0
        assert r.false_positives == 0
        assert r.true_detections == 0
        assert r.total_iocs == 0
        assert r.cost_per_month == 0.0
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = ThreatFeedAnalysis()
        assert a.id
        assert a.feed_name == ""
        assert a.recommended_action == ""
        assert a.risk_assessment == 0.0
        assert a.feed_tier == FeedTier.STANDARD
        assert a.created_at > 0

    def test_report_defaults(self) -> None:
        rpt = ThreatFeedReport()
        assert rpt.total_records == 0
        assert rpt.total_analyses == 0
        assert rpt.avg_quality_score == 0.0
        assert rpt.by_quality_metric == {}
        assert rpt.by_feed_tier == {}
        assert rpt.by_quality_trend == {}
        assert rpt.low_quality_feeds == []
        assert rpt.recommendations == []


class TestThreatFeedQualityEngine:
    @pytest.fixture()
    def engine(self) -> ThreatFeedQualityEngine:
        return ThreatFeedQualityEngine(max_records=100)

    def test_add_record(self, engine: ThreatFeedQualityEngine) -> None:
        rec = engine.add_record(
            feed_name="AlienVault OTX",
            quality_metric=FeedQualityMetric.COVERAGE,
            feed_tier=FeedTier.PREMIUM,
            quality_trend=QualityTrend.IMPROVING,
            quality_score=0.85,
            false_positives=10,
            true_detections=200,
            total_iocs=5000,
            cost_per_month=500.0,
        )
        assert isinstance(rec, ThreatFeedRecord)
        assert rec.feed_name == "AlienVault OTX"
        assert rec.quality_score == 0.85

    def test_add_record_defaults(self, engine: ThreatFeedQualityEngine) -> None:
        rec = engine.add_record()
        assert rec.feed_tier == FeedTier.STANDARD
        assert rec.quality_trend == QualityTrend.STABLE
        assert rec.quality_score == 0.0

    def test_process_found_high_quality(self, engine: ThreatFeedQualityEngine) -> None:
        rec = engine.add_record(feed_name="good-feed", quality_score=0.9)
        result = engine.process(rec.id)
        assert isinstance(result, ThreatFeedAnalysis)
        assert "performing well" in result.recommended_action
        assert result.risk_assessment == 10.0

    def test_process_found_moderate_quality(self, engine: ThreatFeedQualityEngine) -> None:
        rec = engine.add_record(feed_name="ok-feed", quality_score=0.6)
        result = engine.process(rec.id)
        assert isinstance(result, ThreatFeedAnalysis)
        assert "moderate" in result.recommended_action

    def test_process_found_poor_quality(self, engine: ThreatFeedQualityEngine) -> None:
        rec = engine.add_record(feed_name="bad-feed", quality_score=0.3)
        result = engine.process(rec.id)
        assert isinstance(result, ThreatFeedAnalysis)
        assert "poor" in result.recommended_action
        assert result.risk_assessment == 70.0

    def test_process_not_found(self, engine: ThreatFeedQualityEngine) -> None:
        result = engine.process("nonexistent")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"
        assert result["key"] == "nonexistent"

    def test_generate_report_populated(self, engine: ThreatFeedQualityEngine) -> None:
        engine.add_record(
            feed_name="feed-a",
            feed_tier=FeedTier.PREMIUM,
            quality_score=0.9,
            quality_trend=QualityTrend.STABLE,
        )
        engine.add_record(
            feed_name="feed-b",
            feed_tier=FeedTier.COMMUNITY,
            quality_score=0.3,
            quality_trend=QualityTrend.DEGRADING,
        )
        report = engine.generate_report()
        assert isinstance(report, ThreatFeedReport)
        assert report.total_records == 2
        assert report.avg_quality_score == 0.6
        assert "feed-b" in report.low_quality_feeds
        assert "premium" in report.by_feed_tier
        assert len(report.recommendations) >= 1

    def test_generate_report_empty(self, engine: ThreatFeedQualityEngine) -> None:
        report = engine.generate_report()
        assert report.total_records == 0
        assert report.avg_quality_score == 0.0

    def test_generate_report_healthy(self, engine: ThreatFeedQualityEngine) -> None:
        engine.add_record(
            feed_name="healthy",
            quality_score=0.9,
            quality_trend=QualityTrend.STABLE,
        )
        report = engine.generate_report()
        assert any("healthy" in r for r in report.recommendations)

    def test_get_stats(self, engine: ThreatFeedQualityEngine) -> None:
        engine.add_record(feed_tier=FeedTier.INTERNAL)
        stats = engine.get_stats()
        assert stats["total_records"] == 1
        assert stats["total_analyses"] == 0
        assert "internal" in stats["feed_tier_distribution"]

    def test_clear_data(self, engine: ThreatFeedQualityEngine) -> None:
        engine.add_record()
        rec = engine._records[0]
        engine.process(rec.id)
        result = engine.clear_data()
        assert result == {"status": "cleared"}
        assert engine.get_stats()["total_records"] == 0
        assert engine.get_stats()["total_analyses"] == 0

    def test_ring_buffer_eviction(self) -> None:
        engine = ThreatFeedQualityEngine(max_records=3)
        for i in range(5):
            engine.add_record(feed_name=f"feed-{i}")
        assert engine.get_stats()["total_records"] == 3
        names = [r.feed_name for r in engine._records]
        assert "feed-0" not in names
        assert "feed-4" in names

    def test_rank_feeds_by_quality(self, engine: ThreatFeedQualityEngine) -> None:
        engine.add_record(
            feed_name="top-feed",
            quality_score=0.95,
            false_positives=1,
            true_detections=100,
        )
        engine.add_record(
            feed_name="low-feed",
            quality_score=0.3,
            false_positives=50,
            true_detections=10,
        )
        ranked = engine.rank_feeds_by_quality()
        assert len(ranked) == 2
        assert ranked[0]["feed_name"] == "top-feed"
        assert ranked[0]["avg_quality_score"] == 0.95

    def test_rank_feeds_by_quality_empty(self, engine: ThreatFeedQualityEngine) -> None:
        assert engine.rank_feeds_by_quality() == []

    def test_detect_feed_overlap(self, engine: ThreatFeedQualityEngine) -> None:
        engine.add_record(feed_name="feed-a", total_iocs=1000)
        engine.add_record(feed_name="feed-b", total_iocs=950)
        overlaps = engine.detect_feed_overlap()
        assert len(overlaps) == 1
        assert overlaps[0]["overlap_ratio_pct"] == 95.0

    def test_detect_feed_overlap_no_overlap(self, engine: ThreatFeedQualityEngine) -> None:
        engine.add_record(feed_name="feed-a", total_iocs=1000)
        engine.add_record(feed_name="feed-b", total_iocs=100)
        overlaps = engine.detect_feed_overlap()
        assert len(overlaps) == 0

    def test_detect_feed_overlap_empty(self, engine: ThreatFeedQualityEngine) -> None:
        assert engine.detect_feed_overlap() == []

    def test_compute_feed_roi(self, engine: ThreatFeedQualityEngine) -> None:
        engine.add_record(
            feed_name="valuable",
            true_detections=100,
            cost_per_month=200.0,
        )
        roi = engine.compute_feed_roi()
        assert len(roi) == 1
        assert roi[0]["feed_name"] == "valuable"
        assert roi[0]["total_detections"] == 100
        assert roi[0]["cost_per_detection"] == 2.0
        assert roi[0]["roi_score"] == 0.5

    def test_compute_feed_roi_zero_cost(self, engine: ThreatFeedQualityEngine) -> None:
        engine.add_record(
            feed_name="free-feed",
            true_detections=50,
            cost_per_month=0.0,
        )
        roi = engine.compute_feed_roi()
        assert roi[0]["roi_score"] == 0.0

    def test_compute_feed_roi_empty(self, engine: ThreatFeedQualityEngine) -> None:
        assert engine.compute_feed_roi() == []
