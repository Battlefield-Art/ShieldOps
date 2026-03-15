"""Tests for RBA-inspired security engines — RiskAggregationEngine,
MitreAttackMapperEngine, SecuritySignalCorrelationEngine."""

from __future__ import annotations

from shieldops.security.mitre_attack_mapper_engine import (
    AttackPhase,
    DetectionCoverage,
    MappingConfidence,
    MitreAttackAnalysis,
    MitreAttackMapperEngine,
    MitreAttackRecord,
    MitreAttackReport,
)
from shieldops.security.risk_aggregation_engine import (
    AggregationStrategy,
    RiskAggregationAnalysis,
    RiskAggregationEngine,
    RiskAggregationRecord,
    RiskAggregationReport,
    RiskSource,
    RiskTier,
)
from shieldops.security.security_signal_correlation_engine import (
    AlertFidelity,
    CorrelationType,
    SecuritySignalAnalysis,
    SecuritySignalCorrelationEngine,
    SecuritySignalRecord,
    SecuritySignalReport,
    SignalSource,
)

# ===========================================================================
# RiskAggregationEngine
# ===========================================================================


class TestRiskAggregationEnums:
    def test_risk_source_values(self) -> None:
        assert RiskSource.IDS == "ids"
        assert RiskSource.EDR == "edr"
        assert RiskSource.SIEM == "siem"
        assert RiskSource.NDR == "ndr"
        assert RiskSource.DLP == "dlp"
        assert RiskSource.UEBA == "ueba"
        assert RiskSource.CSPM == "cspm"

    def test_aggregation_strategy_values(self) -> None:
        assert AggregationStrategy.WEIGHTED_SUM == "weighted_sum"
        assert AggregationStrategy.MAX_SCORE == "max_score"
        assert AggregationStrategy.BAYESIAN == "bayesian"
        assert AggregationStrategy.TEMPORAL_DECAY == "temporal_decay"

    def test_risk_tier_values(self) -> None:
        assert RiskTier.INFORMATIONAL == "informational"
        assert RiskTier.LOW == "low"
        assert RiskTier.MEDIUM == "medium"
        assert RiskTier.HIGH == "high"
        assert RiskTier.CRITICAL == "critical"


class TestRiskAggregationModels:
    def test_record_defaults(self) -> None:
        r = RiskAggregationRecord()
        assert r.id
        assert r.entity == ""
        assert r.entity_type == ""
        assert r.risk_source == RiskSource.SIEM
        assert r.aggregation_strategy == AggregationStrategy.WEIGHTED_SUM
        assert r.risk_tier == RiskTier.LOW
        assert r.raw_score == 0.0
        assert r.weighted_score == 0.0
        assert r.mitre_tactic == ""
        assert r.description == ""
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = RiskAggregationAnalysis()
        assert a.id
        assert a.entity == ""
        assert a.composite_score == 0.0
        assert a.observation_count == 0
        assert a.unique_tactics == 0
        assert a.risk_tier == RiskTier.LOW
        assert a.needs_action is False
        assert a.description == ""
        assert a.created_at > 0

    def test_report_defaults(self) -> None:
        r = RiskAggregationReport()
        assert r.id
        assert r.total_records == 0
        assert r.total_analyses == 0
        assert r.avg_composite_score == 0.0
        assert r.by_risk_source == {}
        assert r.by_aggregation_strategy == {}
        assert r.by_risk_tier == {}
        assert r.critical_entities == []
        assert r.recommendations == []
        assert r.generated_at > 0


class TestRiskAggregationAddRecord:
    def test_basic(self) -> None:
        eng = RiskAggregationEngine()
        r = eng.add_record(
            entity="user-001",
            entity_type="user",
            risk_source=RiskSource.EDR,
            aggregation_strategy=AggregationStrategy.WEIGHTED_SUM,
            risk_tier=RiskTier.MEDIUM,
            raw_score=40.0,
            weighted_score=50.0,
            mitre_tactic="initial_access",
            description="EDR alert",
        )
        assert r.entity == "user-001"
        assert r.risk_source == RiskSource.EDR
        assert r.weighted_score == 50.0

    def test_ring_buffer_eviction(self) -> None:
        eng = RiskAggregationEngine(max_records=3)
        for i in range(5):
            eng.add_record(entity=f"ent-{i}")
        assert len(eng._records) == 3
        assert eng._records[0].entity == "ent-2"


class TestRiskAggregationProcess:
    def test_found(self) -> None:
        eng = RiskAggregationEngine()
        r = eng.add_record(
            entity="host-01",
            weighted_score=45.0,
            mitre_tactic="lateral_movement",
        )
        result = eng.process(r.id)
        assert isinstance(result, RiskAggregationAnalysis)
        assert result.entity == "host-01"
        assert result.composite_score == 45.0
        assert result.observation_count == 1

    def test_not_found(self) -> None:
        eng = RiskAggregationEngine()
        result = eng.process("nonexistent")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"


class TestRiskAggregationReport:
    def test_populated(self) -> None:
        eng = RiskAggregationEngine()
        eng.add_record(
            entity="user-001",
            risk_source=RiskSource.IDS,
            risk_tier=RiskTier.HIGH,
            weighted_score=75.0,
        )
        eng.add_record(
            entity="user-002",
            risk_source=RiskSource.EDR,
            risk_tier=RiskTier.LOW,
            weighted_score=20.0,
        )
        report = eng.generate_report()
        assert isinstance(report, RiskAggregationReport)
        assert report.total_records == 2
        assert report.avg_composite_score == 47.5
        assert "ids" in report.by_risk_source
        assert len(report.recommendations) > 0

    def test_empty(self) -> None:
        eng = RiskAggregationEngine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert "healthy" in report.recommendations[0]


class TestRiskAggregationStats:
    def test_empty(self) -> None:
        eng = RiskAggregationEngine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0
        assert stats["total_analyses"] == 0
        assert stats["source_distribution"] == {}

    def test_populated(self) -> None:
        eng = RiskAggregationEngine()
        eng.add_record(entity="ent-1", risk_source=RiskSource.SIEM)
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_entities"] == 1
        assert "siem" in stats["source_distribution"]


class TestRiskAggregationClear:
    def test_clears(self) -> None:
        eng = RiskAggregationEngine()
        eng.add_record(entity="ent-1")
        r = eng.add_record(entity="ent-2")
        eng.process(r.id)
        result = eng.clear_data()
        assert result == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


class TestComputeEntityRisk:
    def test_with_data(self) -> None:
        eng = RiskAggregationEngine()
        eng.add_record(
            entity="user-X",
            weighted_score=30.0,
            mitre_tactic="initial_access",
            risk_source=RiskSource.IDS,
        )
        eng.add_record(
            entity="user-X",
            weighted_score=50.0,
            mitre_tactic="lateral_movement",
            risk_source=RiskSource.EDR,
        )
        result = eng.compute_entity_risk("user-X")
        assert result["entity"] == "user-X"
        assert result["composite_score"] == 80.0
        assert result["observation_count"] == 2
        assert result["unique_tactics"] == 2
        assert result["risk_tier"] == "high"

    def test_no_data(self) -> None:
        eng = RiskAggregationEngine()
        result = eng.compute_entity_risk("ghost")
        assert result["composite_score"] == 0.0
        assert result["observation_count"] == 0


class TestDetectKillChainProgression:
    def test_multi_tactic_entities(self) -> None:
        eng = RiskAggregationEngine()
        eng.add_record(entity="host-A", mitre_tactic="initial_access", weighted_score=20.0)
        eng.add_record(entity="host-A", mitre_tactic="lateral_movement", weighted_score=30.0)
        eng.add_record(entity="host-A", mitre_tactic="exfiltration", weighted_score=40.0)
        eng.add_record(entity="host-B", mitre_tactic="initial_access", weighted_score=10.0)
        results = eng.detect_kill_chain_progression()
        assert len(results) == 1
        assert results[0]["entity"] == "host-A"
        assert results[0]["tactic_count"] == 3
        assert results[0]["composite_score"] == 90.0

    def test_empty(self) -> None:
        eng = RiskAggregationEngine()
        assert eng.detect_kill_chain_progression() == []


class TestRankEntitiesByRisk:
    def test_ranking(self) -> None:
        eng = RiskAggregationEngine()
        eng.add_record(entity="low-risk", weighted_score=10.0)
        eng.add_record(entity="high-risk", weighted_score=90.0)
        eng.add_record(entity="mid-risk", weighted_score=50.0)
        results = eng.rank_entities_by_risk()
        assert len(results) == 3
        assert results[0]["entity"] == "high-risk"
        assert results[0]["rank"] == 1
        assert results[2]["entity"] == "low-risk"
        assert results[2]["rank"] == 3

    def test_empty(self) -> None:
        eng = RiskAggregationEngine()
        assert eng.rank_entities_by_risk() == []


# ===========================================================================
# MitreAttackMapperEngine
# ===========================================================================


class TestMitreAttackEnums:
    def test_attack_phase_values(self) -> None:
        assert AttackPhase.RECONNAISSANCE == "reconnaissance"
        assert AttackPhase.WEAPONIZATION == "weaponization"
        assert AttackPhase.DELIVERY == "delivery"
        assert AttackPhase.EXPLOITATION == "exploitation"
        assert AttackPhase.INSTALLATION == "installation"
        assert AttackPhase.COMMAND_CONTROL == "command_control"
        assert AttackPhase.ACTIONS_ON_OBJECTIVES == "actions_on_objectives"

    def test_detection_coverage_values(self) -> None:
        assert DetectionCoverage.FULL == "full"
        assert DetectionCoverage.PARTIAL == "partial"
        assert DetectionCoverage.NONE == "none"
        assert DetectionCoverage.UNTESTED == "untested"

    def test_mapping_confidence_values(self) -> None:
        assert MappingConfidence.HIGH == "high"
        assert MappingConfidence.MEDIUM == "medium"
        assert MappingConfidence.LOW == "low"
        assert MappingConfidence.UNMAPPED == "unmapped"


class TestMitreAttackModels:
    def test_record_defaults(self) -> None:
        r = MitreAttackRecord()
        assert r.id
        assert r.detection_name == ""
        assert r.tactic == ""
        assert r.technique == ""
        assert r.attack_phase == AttackPhase.RECONNAISSANCE
        assert r.detection_coverage == DetectionCoverage.UNTESTED
        assert r.mapping_confidence == MappingConfidence.UNMAPPED
        assert r.score == 0.0
        assert r.description == ""
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = MitreAttackAnalysis()
        assert a.id
        assert a.detection_name == ""
        assert a.tactic == ""
        assert a.coverage_score == 0.0
        assert a.confidence_avg == 0.0
        assert a.gap_count == 0
        assert a.detection_coverage == DetectionCoverage.UNTESTED
        assert a.description == ""
        assert a.created_at > 0

    def test_report_defaults(self) -> None:
        r = MitreAttackReport()
        assert r.id
        assert r.total_records == 0
        assert r.total_analyses == 0
        assert r.avg_confidence == 0.0
        assert r.by_attack_phase == {}
        assert r.by_detection_coverage == {}
        assert r.by_mapping_confidence == {}
        assert r.coverage_gaps == []
        assert r.recommendations == []
        assert r.generated_at > 0


class TestMitreAttackAddRecord:
    def test_basic(self) -> None:
        eng = MitreAttackMapperEngine()
        r = eng.add_record(
            detection_name="brute-force-detect",
            tactic="credential_access",
            technique="T1110",
            attack_phase=AttackPhase.EXPLOITATION,
            detection_coverage=DetectionCoverage.FULL,
            mapping_confidence=MappingConfidence.HIGH,
            score=85.0,
        )
        assert r.detection_name == "brute-force-detect"
        assert r.tactic == "credential_access"
        assert r.technique == "T1110"
        assert r.attack_phase == AttackPhase.EXPLOITATION

    def test_ring_buffer_eviction(self) -> None:
        eng = MitreAttackMapperEngine(max_records=3)
        for i in range(5):
            eng.add_record(detection_name=f"DET-{i}")
        assert len(eng._records) == 3
        assert eng._records[0].detection_name == "DET-2"


class TestMitreAttackProcess:
    def test_found(self) -> None:
        eng = MitreAttackMapperEngine()
        r = eng.add_record(
            detection_name="phishing-detect",
            tactic="initial_access",
            detection_coverage=DetectionCoverage.FULL,
            mapping_confidence=MappingConfidence.HIGH,
        )
        result = eng.process(r.id)
        assert isinstance(result, MitreAttackAnalysis)
        assert result.tactic == "initial_access"
        assert result.coverage_score == 100.0
        assert result.confidence_avg == 1.0

    def test_not_found(self) -> None:
        eng = MitreAttackMapperEngine()
        result = eng.process("nonexistent")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"


class TestMitreAttackGenerateReport:
    def test_populated(self) -> None:
        eng = MitreAttackMapperEngine()
        eng.add_record(
            detection_name="DET-1",
            tactic="initial_access",
            attack_phase=AttackPhase.DELIVERY,
            detection_coverage=DetectionCoverage.FULL,
            mapping_confidence=MappingConfidence.HIGH,
        )
        eng.add_record(
            detection_name="DET-2",
            tactic="lateral_movement",
            attack_phase=AttackPhase.EXPLOITATION,
            detection_coverage=DetectionCoverage.NONE,
            mapping_confidence=MappingConfidence.LOW,
        )
        report = eng.generate_report()
        assert isinstance(report, MitreAttackReport)
        assert report.total_records == 2
        assert len(report.by_attack_phase) == 2
        assert len(report.recommendations) > 0

    def test_empty(self) -> None:
        eng = MitreAttackMapperEngine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert "healthy" in report.recommendations[0]


class TestMitreAttackStats:
    def test_empty(self) -> None:
        eng = MitreAttackMapperEngine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0
        assert stats["total_analyses"] == 0
        assert stats["phase_distribution"] == {}

    def test_populated(self) -> None:
        eng = MitreAttackMapperEngine()
        eng.add_record(
            tactic="persistence",
            technique="T1053",
            attack_phase=AttackPhase.INSTALLATION,
        )
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_tactics"] == 1
        assert stats["unique_techniques"] == 1
        assert "installation" in stats["phase_distribution"]


class TestMitreAttackClear:
    def test_clears(self) -> None:
        eng = MitreAttackMapperEngine()
        eng.add_record(detection_name="DET-1")
        r = eng.add_record(detection_name="DET-2", tactic="t1")
        eng.process(r.id)
        result = eng.clear_data()
        assert result == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


class TestIdentifyCoverageGaps:
    def test_finds_gaps(self) -> None:
        eng = MitreAttackMapperEngine()
        eng.add_record(
            tactic="initial_access",
            detection_coverage=DetectionCoverage.FULL,
        )
        eng.add_record(
            tactic="lateral_movement",
            detection_coverage=DetectionCoverage.NONE,
        )
        eng.add_record(
            tactic="exfiltration",
            detection_coverage=DetectionCoverage.UNTESTED,
        )
        gaps = eng.identify_coverage_gaps()
        assert len(gaps) == 2
        gap_tactics = {g["tactic"] for g in gaps}
        assert "lateral_movement" in gap_tactics
        assert "exfiltration" in gap_tactics

    def test_no_gaps(self) -> None:
        eng = MitreAttackMapperEngine()
        eng.add_record(
            tactic="initial_access",
            detection_coverage=DetectionCoverage.FULL,
        )
        assert eng.identify_coverage_gaps() == []


class TestComputeAttackSurfaceCoverage:
    def test_partial_coverage(self) -> None:
        eng = MitreAttackMapperEngine()
        eng.add_record(
            tactic="t1",
            attack_phase=AttackPhase.DELIVERY,
            detection_coverage=DetectionCoverage.FULL,
        )
        eng.add_record(
            tactic="t2",
            attack_phase=AttackPhase.EXPLOITATION,
            detection_coverage=DetectionCoverage.NONE,
        )
        result = eng.compute_attack_surface_coverage()
        assert result["covered_phases"] == 1
        assert result["total_phases"] == 7
        assert result["covered_tactics"] == 1
        assert result["total_tactics"] == 2
        assert result["tactic_coverage_pct"] == 50.0

    def test_empty(self) -> None:
        eng = MitreAttackMapperEngine()
        result = eng.compute_attack_surface_coverage()
        assert result["covered_phases"] == 0
        assert result["tactic_coverage_pct"] == 0.0


class TestPrioritizeDetectionDevelopment:
    def test_ranks_uncovered(self) -> None:
        eng = MitreAttackMapperEngine()
        eng.add_record(
            technique="T1110",
            tactic="credential_access",
            attack_phase=AttackPhase.EXPLOITATION,
            detection_coverage=DetectionCoverage.NONE,
            score=90.0,
        )
        eng.add_record(
            technique="T1053",
            tactic="persistence",
            attack_phase=AttackPhase.INSTALLATION,
            detection_coverage=DetectionCoverage.NONE,
            score=50.0,
        )
        eng.add_record(
            technique="T1078",
            tactic="initial_access",
            attack_phase=AttackPhase.DELIVERY,
            detection_coverage=DetectionCoverage.FULL,
            score=80.0,
        )
        results = eng.prioritize_detection_development()
        assert len(results) == 2
        assert results[0]["technique"] == "T1110"
        assert results[0]["priority"] == "high"
        assert results[1]["technique"] == "T1053"
        assert results[1]["priority"] == "medium"

    def test_empty(self) -> None:
        eng = MitreAttackMapperEngine()
        assert eng.prioritize_detection_development() == []


# ===========================================================================
# SecuritySignalCorrelationEngine
# ===========================================================================


class TestSignalCorrelationEnums:
    def test_signal_source_values(self) -> None:
        assert SignalSource.FIREWALL == "firewall"
        assert SignalSource.ENDPOINT == "endpoint"
        assert SignalSource.NETWORK == "network"
        assert SignalSource.IDENTITY == "identity"
        assert SignalSource.CLOUD == "cloud"
        assert SignalSource.APPLICATION == "application"

    def test_correlation_type_values(self) -> None:
        assert CorrelationType.TEMPORAL == "temporal"
        assert CorrelationType.ENTITY_BASED == "entity_based"
        assert CorrelationType.TACTIC_CHAIN == "tactic_chain"
        assert CorrelationType.STATISTICAL == "statistical"

    def test_alert_fidelity_values(self) -> None:
        assert AlertFidelity.LOW == "low"
        assert AlertFidelity.MEDIUM == "medium"
        assert AlertFidelity.HIGH == "high"
        assert AlertFidelity.CONFIRMED == "confirmed"


class TestSignalCorrelationModels:
    def test_record_defaults(self) -> None:
        r = SecuritySignalRecord()
        assert r.id
        assert r.signal_id == ""
        assert r.signal_source == SignalSource.NETWORK
        assert r.correlation_type == CorrelationType.TEMPORAL
        assert r.alert_fidelity == AlertFidelity.LOW
        assert r.raw_confidence == 0.0
        assert r.correlated_confidence == 0.0
        assert r.entity == ""
        assert r.description == ""
        assert r.created_at > 0

    def test_analysis_defaults(self) -> None:
        a = SecuritySignalAnalysis()
        assert a.id
        assert a.signal_id == ""
        assert a.correlation_count == 0
        assert a.fidelity_upgrade is False
        assert a.original_fidelity == AlertFidelity.LOW
        assert a.final_fidelity == AlertFidelity.LOW
        assert a.description == ""
        assert a.created_at > 0

    def test_report_defaults(self) -> None:
        r = SecuritySignalReport()
        assert r.id
        assert r.total_records == 0
        assert r.total_analyses == 0
        assert r.avg_correlated_confidence == 0.0
        assert r.by_signal_source == {}
        assert r.by_correlation_type == {}
        assert r.by_alert_fidelity == {}
        assert r.high_fidelity_alerts == []
        assert r.recommendations == []
        assert r.generated_at > 0


class TestSignalCorrelationAddRecord:
    def test_basic(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        r = eng.add_record(
            signal_id="SIG-001",
            signal_source=SignalSource.FIREWALL,
            correlation_type=CorrelationType.TEMPORAL,
            alert_fidelity=AlertFidelity.LOW,
            raw_confidence=30.0,
            correlated_confidence=45.0,
            entity="host-01",
        )
        assert r.signal_id == "SIG-001"
        assert r.signal_source == SignalSource.FIREWALL
        assert r.raw_confidence == 30.0

    def test_ring_buffer_eviction(self) -> None:
        eng = SecuritySignalCorrelationEngine(max_records=3)
        for i in range(5):
            eng.add_record(signal_id=f"SIG-{i}")
        assert len(eng._records) == 3
        assert eng._records[0].signal_id == "SIG-2"


class TestSignalCorrelationProcess:
    def test_found(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        r = eng.add_record(
            signal_id="SIG-001",
            entity="host-01",
            alert_fidelity=AlertFidelity.LOW,
            correlated_confidence=50.0,
        )
        result = eng.process(r.id)
        assert isinstance(result, SecuritySignalAnalysis)
        assert result.signal_id == "SIG-001"
        assert result.correlation_count == 1

    def test_not_found(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        result = eng.process("nonexistent")
        assert isinstance(result, dict)
        assert result["status"] == "not_found"

    def test_fidelity_upgrade(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        eng.add_record(
            signal_id="SIG-A",
            entity="host-01",
            signal_source=SignalSource.FIREWALL,
            alert_fidelity=AlertFidelity.LOW,
            correlated_confidence=70.0,
        )
        r = eng.add_record(
            signal_id="SIG-B",
            entity="host-01",
            signal_source=SignalSource.ENDPOINT,
            alert_fidelity=AlertFidelity.LOW,
            correlated_confidence=80.0,
        )
        result = eng.process(r.id)
        assert isinstance(result, SecuritySignalAnalysis)
        assert result.fidelity_upgrade is True
        assert result.final_fidelity == AlertFidelity.HIGH


class TestSignalCorrelationGenerateReport:
    def test_populated(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        eng.add_record(
            signal_id="SIG-001",
            signal_source=SignalSource.FIREWALL,
            alert_fidelity=AlertFidelity.HIGH,
            correlated_confidence=85.0,
        )
        eng.add_record(
            signal_id="SIG-002",
            signal_source=SignalSource.ENDPOINT,
            alert_fidelity=AlertFidelity.LOW,
            correlated_confidence=25.0,
        )
        report = eng.generate_report()
        assert isinstance(report, SecuritySignalReport)
        assert report.total_records == 2
        assert report.avg_correlated_confidence == 55.0
        assert "firewall" in report.by_signal_source
        assert len(report.recommendations) > 0

    def test_empty(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        report = eng.generate_report()
        assert report.total_records == 0
        assert "healthy" in report.recommendations[0]


class TestSignalCorrelationStats:
    def test_empty(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        stats = eng.get_stats()
        assert stats["total_records"] == 0
        assert stats["total_analyses"] == 0
        assert stats["source_distribution"] == {}

    def test_populated(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        eng.add_record(
            signal_id="SIG-1",
            signal_source=SignalSource.CLOUD,
            entity="svc-01",
        )
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert stats["unique_entities"] == 1
        assert stats["unique_signals"] == 1
        assert "cloud" in stats["source_distribution"]


class TestSignalCorrelationClear:
    def test_clears(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        eng.add_record(signal_id="SIG-1", entity="e1")
        r = eng.add_record(signal_id="SIG-2", entity="e2")
        eng.process(r.id)
        result = eng.clear_data()
        assert result == {"status": "cleared"}
        assert len(eng._records) == 0
        assert len(eng._analyses) == 0


class TestCorrelateByEntity:
    def test_with_data(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        eng.add_record(
            signal_id="SIG-1",
            entity="host-X",
            signal_source=SignalSource.FIREWALL,
            raw_confidence=60.0,
            correlated_confidence=70.0,
        )
        eng.add_record(
            signal_id="SIG-2",
            entity="host-X",
            signal_source=SignalSource.ENDPOINT,
            raw_confidence=80.0,
            correlated_confidence=85.0,
        )
        result = eng.correlate_by_entity("host-X")
        assert result["entity"] == "host-X"
        assert result["signal_count"] == 2
        assert len(result["unique_sources"]) == 2
        assert result["correlated_confidence"] > result["avg_raw_confidence"]

    def test_no_data(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        result = eng.correlate_by_entity("ghost")
        assert result["signal_count"] == 0
        assert result["correlated_confidence"] == 0.0


class TestMeasureNoiseReduction:
    def test_with_data(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        eng.add_record(
            signal_id="S1",
            entity="e1",
            correlated_confidence=80.0,
            signal_source=SignalSource.FIREWALL,
        )
        eng.add_record(
            signal_id="S2",
            entity="e1",
            correlated_confidence=85.0,
            signal_source=SignalSource.ENDPOINT,
        )
        eng.add_record(
            signal_id="S3",
            entity="e1",
            correlated_confidence=90.0,
            signal_source=SignalSource.CLOUD,
        )
        eng.add_record(
            signal_id="S4",
            entity="e2",
            correlated_confidence=20.0,
            signal_source=SignalSource.NETWORK,
        )
        result = eng.measure_noise_reduction()
        assert result["total_raw_signals"] == 4
        assert result["correlated_alerts"] == 2
        assert result["noise_reduction_pct"] == 50.0

    def test_empty(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        result = eng.measure_noise_reduction()
        assert result["total_raw_signals"] == 0
        assert result["noise_reduction_pct"] == 0.0


class TestIdentifyCorrelationPatterns:
    def test_finds_patterns(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        eng.add_record(entity="e1", signal_source=SignalSource.FIREWALL)
        eng.add_record(entity="e1", signal_source=SignalSource.ENDPOINT)
        eng.add_record(entity="e2", signal_source=SignalSource.FIREWALL)
        eng.add_record(entity="e2", signal_source=SignalSource.ENDPOINT)
        eng.add_record(entity="e3", signal_source=SignalSource.CLOUD)
        results = eng.identify_correlation_patterns()
        assert len(results) == 2
        # endpoint+firewall pattern occurs twice
        top = results[0]
        assert top["occurrence_count"] == 2
        assert top["source_count"] == 2

    def test_empty(self) -> None:
        eng = SecuritySignalCorrelationEngine()
        assert eng.identify_correlation_patterns() == []
