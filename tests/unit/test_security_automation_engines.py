"""Tests for security automation engines:
ThreatHuntAutomationEngine, SecurityPlaybookSelectorEngine,
AttackSurfaceContinuousScorerEngine, IncidentAutoClassificationEngine."""

from __future__ import annotations

from shieldops.security.threat_hunt_automation_engine import (
    HuntOutcome,
    HuntPriority,
    HuntTrigger,
    ThreatHuntAnalysis,
    ThreatHuntAutomationEngine,
    ThreatHuntRecord,
    ThreatHuntReport,
)
from shieldops.security.security_playbook_selector_engine import (
    MatchStrategy,
    PlaybookCategory,
    PlaybookSelectorAnalysis,
    PlaybookSelectorRecord,
    PlaybookSelectorReport,
    SecurityPlaybookSelectorEngine,
    SelectionConfidence,
)
from shieldops.security.attack_surface_continuous_scorer_engine import (
    AttackSurfaceAnalysis,
    AttackSurfaceContinuousScorerEngine,
    AttackSurfaceRecord,
    AttackSurfaceReport,
    ExposureLevel,
    RiskChange,
    SurfaceComponent,
)
from shieldops.security.incident_auto_classification_engine import (
    ClassificationConfidence,
    ClassificationMethod,
    IncidentAutoClassificationEngine,
    IncidentClass,
    IncidentClassificationAnalysis,
    IncidentClassificationRecord,
    IncidentClassificationReport,
)


# =========================================================================
# ThreatHuntAutomationEngine
# =========================================================================


class TestThreatHuntEnums:
    def test_trigger_rba(self):
        assert HuntTrigger.RBA_SCORE == "rba_score"

    def test_trigger_mitre(self):
        assert HuntTrigger.MITRE_GAP == "mitre_gap"

    def test_trigger_intel(self):
        assert HuntTrigger.INTEL_FEED == "intel_feed"

    def test_trigger_behavioral(self):
        assert HuntTrigger.BEHAVIORAL_ANOMALY == "behavioral_anomaly"

    def test_priority_immediate(self):
        assert HuntPriority.IMMEDIATE == "immediate"

    def test_priority_background(self):
        assert HuntPriority.BACKGROUND == "background"

    def test_outcome_confirmed(self):
        assert HuntOutcome.CONFIRMED_THREAT == "confirmed_threat"

    def test_outcome_false_positive(self):
        assert HuntOutcome.FALSE_POSITIVE == "false_positive"

    def test_outcome_escalation(self):
        assert HuntOutcome.NEEDS_ESCALATION == "needs_escalation"


class TestThreatHuntModels:
    def test_record_defaults(self):
        r = ThreatHuntRecord()
        assert r.id
        assert r.hunt_trigger == HuntTrigger.RBA_SCORE
        assert r.risk_score == 0.0

    def test_analysis_defaults(self):
        a = ThreatHuntAnalysis()
        assert a.id
        assert a.recommended_action == ""

    def test_report_defaults(self):
        rpt = ThreatHuntReport()
        assert rpt.total_records == 0
        assert rpt.confirmed_threat_rate == 0.0


class TestThreatHuntAddRecord:
    def test_basic(self):
        eng = ThreatHuntAutomationEngine()
        rec = eng.add_record(
            entity_id="host-1",
            hunt_trigger=HuntTrigger.RBA_SCORE,
            risk_score=0.85,
        )
        assert rec.entity_id == "host-1"
        assert rec.risk_score == 0.85

    def test_eviction(self):
        eng = ThreatHuntAutomationEngine(max_records=3)
        for i in range(5):
            eng.add_record(entity_id=f"e-{i}")
        assert len(eng._records) == 3


class TestThreatHuntProcess:
    def test_found(self):
        eng = ThreatHuntAutomationEngine()
        rec = eng.add_record(entity_id="h1", risk_score=0.9)
        result = eng.process(rec.id)
        assert isinstance(result, ThreatHuntAnalysis)
        assert result.hunt_priority == HuntPriority.IMMEDIATE

    def test_moderate_risk(self):
        eng = ThreatHuntAutomationEngine()
        rec = eng.add_record(entity_id="h2", risk_score=0.6)
        result = eng.process(rec.id)
        assert isinstance(result, ThreatHuntAnalysis)
        assert result.hunt_priority == HuntPriority.HIGH

    def test_not_found(self):
        eng = ThreatHuntAutomationEngine()
        result = eng.process("missing")
        assert result == {"status": "not_found", "key": "missing"}


class TestThreatHuntReport:
    def test_populated(self):
        eng = ThreatHuntAutomationEngine()
        eng.add_record(
            entity_id="h1",
            risk_score=0.9,
            hunt_outcome=HuntOutcome.CONFIRMED_THREAT,
        )
        eng.add_record(
            entity_id="h2",
            risk_score=0.3,
            hunt_outcome=HuntOutcome.FALSE_POSITIVE,
        )
        rpt = eng.generate_report()
        assert isinstance(rpt, ThreatHuntReport)
        assert rpt.total_records == 2
        assert rpt.confirmed_threat_rate == 50.0

    def test_empty(self):
        eng = ThreatHuntAutomationEngine()
        rpt = eng.generate_report()
        assert len(rpt.recommendations) > 0


class TestThreatHuntStatsAndClear:
    def test_stats(self):
        eng = ThreatHuntAutomationEngine()
        eng.add_record(entity_id="h1")
        stats = eng.get_stats()
        assert stats["total_records"] == 1

    def test_clear(self):
        eng = ThreatHuntAutomationEngine()
        eng.add_record(entity_id="h1")
        result = eng.clear_data()
        assert result == {"status": "cleared"}
        assert len(eng._records) == 0


class TestAutoTriggerHunts:
    def test_high_risk(self):
        eng = ThreatHuntAutomationEngine()
        eng.add_record(entity_id="e1", risk_score=0.95)
        results = eng.auto_trigger_hunts(risk_threshold=0.7)
        assert len(results) == 1
        assert results[0]["recommended_priority"] == "immediate"

    def test_coverage_gap(self):
        eng = ThreatHuntAutomationEngine()
        eng.add_record(entity_id="e1", risk_score=0.3, mitre_tactic="T1")
        results = eng.auto_trigger_hunts()
        assert len(results) == 1
        assert results[0]["has_coverage_gaps"] is True

    def test_no_triggers(self):
        eng = ThreatHuntAutomationEngine()
        eng.add_record(
            entity_id="e1", risk_score=0.3,
            mitre_tactic="T1",
        )
        eng.add_record(
            entity_id="e1", risk_score=0.3,
            mitre_tactic="T2",
        )
        eng.add_record(
            entity_id="e1", risk_score=0.3,
            mitre_tactic="T3",
        )
        results = eng.auto_trigger_hunts()
        assert len(results) == 0


class TestCorrelateHuntToRba:
    def test_strong_correlation(self):
        eng = ThreatHuntAutomationEngine()
        eng.add_record(
            entity_id="e1", risk_score=0.9,
            hunt_outcome=HuntOutcome.CONFIRMED_THREAT,
        )
        results = eng.correlate_hunt_to_rba()
        assert results[0]["rba_correlation"] == "strong"

    def test_weak_correlation(self):
        eng = ThreatHuntAutomationEngine()
        eng.add_record(
            entity_id="e1", risk_score=0.3,
            hunt_outcome=HuntOutcome.FALSE_POSITIVE,
        )
        results = eng.correlate_hunt_to_rba()
        assert results[0]["rba_correlation"] == "weak"


class TestMeasureHuntEffectiveness:
    def test_with_data(self):
        eng = ThreatHuntAutomationEngine()
        eng.add_record(hunt_outcome=HuntOutcome.CONFIRMED_THREAT)
        eng.add_record(hunt_outcome=HuntOutcome.CONFIRMED_THREAT)
        eng.add_record(hunt_outcome=HuntOutcome.FALSE_POSITIVE)
        result = eng.measure_hunt_effectiveness()
        assert result["confirmed_rate"] == 66.67
        assert result["effectiveness_grade"] == "excellent"

    def test_empty(self):
        eng = ThreatHuntAutomationEngine()
        result = eng.measure_hunt_effectiveness()
        assert result["effectiveness_grade"] == "no_data"

    def test_poor_grade(self):
        eng = ThreatHuntAutomationEngine()
        eng.add_record(hunt_outcome=HuntOutcome.FALSE_POSITIVE)
        eng.add_record(hunt_outcome=HuntOutcome.INCONCLUSIVE)
        result = eng.measure_hunt_effectiveness()
        assert result["effectiveness_grade"] == "poor"


# =========================================================================
# SecurityPlaybookSelectorEngine
# =========================================================================


class TestPlaybookEnums:
    def test_category_containment(self):
        assert PlaybookCategory.CONTAINMENT == "containment"

    def test_category_recovery(self):
        assert PlaybookCategory.RECOVERY == "recovery"

    def test_strategy_mitre(self):
        assert MatchStrategy.MITRE_BASED == "mitre_based"

    def test_strategy_ensemble(self):
        assert MatchStrategy.ENSEMBLE == "ensemble"

    def test_confidence_high(self):
        assert SelectionConfidence.HIGH == "high"

    def test_confidence_no_match(self):
        assert SelectionConfidence.NO_MATCH == "no_match"


class TestPlaybookModels:
    def test_record_defaults(self):
        r = PlaybookSelectorRecord()
        assert r.id
        assert r.playbook_category == PlaybookCategory.INVESTIGATION

    def test_analysis_defaults(self):
        a = PlaybookSelectorAnalysis()
        assert a.id
        assert a.confidence_score == 0.0

    def test_report_defaults(self):
        rpt = PlaybookSelectorReport()
        assert rpt.total_records == 0


class TestPlaybookAddRecord:
    def test_basic(self):
        eng = SecurityPlaybookSelectorEngine()
        rec = eng.add_record(
            alert_type="brute_force",
            playbook_id="pb-001",
            success_rate=0.9,
        )
        assert rec.alert_type == "brute_force"
        assert rec.playbook_id == "pb-001"

    def test_eviction(self):
        eng = SecurityPlaybookSelectorEngine(max_records=2)
        for i in range(5):
            eng.add_record(alert_type=f"a-{i}")
        assert len(eng._records) == 2


class TestPlaybookProcess:
    def test_high_confidence(self):
        eng = SecurityPlaybookSelectorEngine()
        rec = eng.add_record(
            playbook_id="pb-1", success_rate=0.9, risk_level=0.8,
        )
        result = eng.process(rec.id)
        assert isinstance(result, PlaybookSelectorAnalysis)
        assert result.selection_confidence == SelectionConfidence.HIGH

    def test_not_found(self):
        eng = SecurityPlaybookSelectorEngine()
        result = eng.process("nope")
        assert result["status"] == "not_found"


class TestPlaybookReport:
    def test_populated(self):
        eng = SecurityPlaybookSelectorEngine()
        eng.add_record(
            alert_type="malware",
            playbook_id="pb-1",
            success_rate=0.85,
        )
        rpt = eng.generate_report()
        assert isinstance(rpt, PlaybookSelectorReport)
        assert rpt.total_records == 1

    def test_empty(self):
        eng = SecurityPlaybookSelectorEngine()
        rpt = eng.generate_report()
        assert len(rpt.recommendations) > 0


class TestPlaybookStatsAndClear:
    def test_stats(self):
        eng = SecurityPlaybookSelectorEngine()
        eng.add_record(alert_type="x")
        assert eng.get_stats()["total_records"] == 1

    def test_clear(self):
        eng = SecurityPlaybookSelectorEngine()
        eng.add_record(alert_type="x")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0


class TestMatchAlertToPlaybook:
    def test_exact_match(self):
        eng = SecurityPlaybookSelectorEngine()
        eng.add_record(
            alert_type="brute_force",
            playbook_id="pb-1",
            mitre_tactic="TA0006",
            success_rate=0.9,
        )
        results = eng.match_alert_to_playbook(
            alert_type="brute_force", mitre_tactic="TA0006",
        )
        assert results[0]["playbook_id"] == "pb-1"
        assert results[0]["confidence"] == "high"

    def test_no_match(self):
        eng = SecurityPlaybookSelectorEngine()
        eng.add_record(
            alert_type="malware", playbook_id="pb-1", mitre_tactic="TA0001",
        )
        results = eng.match_alert_to_playbook(
            alert_type="unknown_type", mitre_tactic="TA9999",
        )
        assert results[0]["confidence"] == "no_match"

    def test_partial_match(self):
        eng = SecurityPlaybookSelectorEngine()
        eng.add_record(
            alert_type="phishing",
            playbook_id="pb-2",
            mitre_tactic="TA0001",
            success_rate=0.6,
        )
        results = eng.match_alert_to_playbook(
            alert_type="other", mitre_tactic="TA0001",
        )
        assert len(results) >= 1


class TestRankPlaybooks:
    def test_ranking(self):
        eng = SecurityPlaybookSelectorEngine()
        eng.add_record(playbook_id="pb-1", success_rate=0.9)
        eng.add_record(playbook_id="pb-2", success_rate=0.4)
        results = eng.rank_playbooks_by_effectiveness()
        assert results[0]["playbook_id"] == "pb-1"
        assert results[0]["rank_tier"] == "top"
        assert results[1]["rank_tier"] == "low"

    def test_empty(self):
        eng = SecurityPlaybookSelectorEngine()
        assert eng.rank_playbooks_by_effectiveness() == []


class TestPlaybookGaps:
    def test_gap_found(self):
        eng = SecurityPlaybookSelectorEngine()
        eng.add_record(alert_type="ransomware", playbook_id="", risk_level=0.9)
        gaps = eng.identify_playbook_gaps()
        assert len(gaps) == 1
        assert gaps[0]["gap_severity"] == "critical"

    def test_no_gap(self):
        eng = SecurityPlaybookSelectorEngine()
        eng.add_record(
            alert_type="malware", playbook_id="pb-1", risk_level=0.5,
        )
        gaps = eng.identify_playbook_gaps()
        assert len(gaps) == 0


# =========================================================================
# AttackSurfaceContinuousScorerEngine
# =========================================================================


class TestSurfaceEnums:
    def test_component_external(self):
        assert SurfaceComponent.EXTERNAL_SERVICE == "external_service"

    def test_component_api(self):
        assert SurfaceComponent.API_ENDPOINT == "api_endpoint"

    def test_exposure_internet(self):
        assert ExposureLevel.INTERNET_FACING == "internet_facing"

    def test_exposure_air_gapped(self):
        assert ExposureLevel.AIR_GAPPED == "air_gapped"

    def test_change_increased(self):
        assert RiskChange.INCREASED == "increased"

    def test_change_new(self):
        assert RiskChange.NEW_EXPOSURE == "new_exposure"


class TestSurfaceModels:
    def test_record_defaults(self):
        r = AttackSurfaceRecord()
        assert r.id
        assert r.surface_component == SurfaceComponent.INTERNAL_SERVICE

    def test_analysis_defaults(self):
        a = AttackSurfaceAnalysis()
        assert a.id
        assert a.composite_risk == 0.0

    def test_report_defaults(self):
        rpt = AttackSurfaceReport()
        assert rpt.total_records == 0


class TestSurfaceAddRecord:
    def test_basic(self):
        eng = AttackSurfaceContinuousScorerEngine()
        rec = eng.add_record(
            component_id="svc-1",
            surface_component=SurfaceComponent.EXTERNAL_SERVICE,
            exposure_level=ExposureLevel.INTERNET_FACING,
            risk_score=0.85,
        )
        assert rec.component_id == "svc-1"
        assert rec.risk_score == 0.85

    def test_eviction(self):
        eng = AttackSurfaceContinuousScorerEngine(max_records=2)
        for i in range(5):
            eng.add_record(component_id=f"c-{i}")
        assert len(eng._records) == 2


class TestSurfaceProcess:
    def test_high_risk(self):
        eng = AttackSurfaceContinuousScorerEngine()
        rec = eng.add_record(
            component_id="svc-1",
            exposure_level=ExposureLevel.INTERNET_FACING,
            risk_score=0.9,
            vulnerability_count=10,
            misconfiguration_count=5,
        )
        result = eng.process(rec.id)
        assert isinstance(result, AttackSurfaceAnalysis)
        assert result.remediation_priority == 1

    def test_low_risk(self):
        eng = AttackSurfaceContinuousScorerEngine()
        rec = eng.add_record(
            exposure_level=ExposureLevel.AIR_GAPPED, risk_score=0.1,
        )
        result = eng.process(rec.id)
        assert isinstance(result, AttackSurfaceAnalysis)
        assert result.remediation_priority == 3

    def test_not_found(self):
        eng = AttackSurfaceContinuousScorerEngine()
        result = eng.process("missing")
        assert result["status"] == "not_found"


class TestSurfaceReport:
    def test_populated(self):
        eng = AttackSurfaceContinuousScorerEngine()
        eng.add_record(
            component_id="svc-1",
            exposure_level=ExposureLevel.INTERNET_FACING,
            risk_score=0.9,
        )
        rpt = eng.generate_report()
        assert isinstance(rpt, AttackSurfaceReport)
        assert rpt.total_records == 1

    def test_empty(self):
        eng = AttackSurfaceContinuousScorerEngine()
        rpt = eng.generate_report()
        assert len(rpt.recommendations) > 0


class TestSurfaceStatsAndClear:
    def test_stats(self):
        eng = AttackSurfaceContinuousScorerEngine()
        eng.add_record(component_id="c1")
        assert eng.get_stats()["total_records"] == 1

    def test_clear(self):
        eng = AttackSurfaceContinuousScorerEngine()
        eng.add_record(component_id="c1")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0


class TestComputeAttackSurfaceScore:
    def test_critical_grade(self):
        eng = AttackSurfaceContinuousScorerEngine()
        eng.add_record(
            exposure_level=ExposureLevel.INTERNET_FACING, risk_score=0.9,
        )
        result = eng.compute_attack_surface_score()
        assert result["grade"] == "critical"
        assert result["internet_facing_score"] == 90.0

    def test_low_grade(self):
        eng = AttackSurfaceContinuousScorerEngine()
        eng.add_record(
            exposure_level=ExposureLevel.AIR_GAPPED, risk_score=0.1,
        )
        result = eng.compute_attack_surface_score()
        assert result["grade"] == "low"

    def test_empty(self):
        eng = AttackSurfaceContinuousScorerEngine()
        result = eng.compute_attack_surface_score()
        assert result["grade"] == "no_data"


class TestDetectExposureChanges:
    def test_new_exposure(self):
        eng = AttackSurfaceContinuousScorerEngine()
        eng.add_record(
            component_id="svc-1",
            risk_change=RiskChange.NEW_EXPOSURE,
            exposure_level=ExposureLevel.INTERNET_FACING,
            risk_score=0.8,
        )
        changes = eng.detect_exposure_changes()
        assert len(changes) == 1
        assert changes[0]["severity"] == "critical"

    def test_increased_risk(self):
        eng = AttackSurfaceContinuousScorerEngine()
        eng.add_record(
            component_id="svc-2",
            risk_change=RiskChange.INCREASED,
            risk_score=0.9,
        )
        changes = eng.detect_exposure_changes()
        assert len(changes) == 1
        assert changes[0]["risk_change"] == "increased"

    def test_no_changes(self):
        eng = AttackSurfaceContinuousScorerEngine()
        eng.add_record(risk_change=RiskChange.UNCHANGED)
        assert eng.detect_exposure_changes() == []


class TestPrioritizeRemediation:
    def test_ordering(self):
        eng = AttackSurfaceContinuousScorerEngine()
        eng.add_record(
            component_id="low",
            exposure_level=ExposureLevel.INTERNAL,
            risk_score=0.2,
        )
        eng.add_record(
            component_id="high",
            exposure_level=ExposureLevel.INTERNET_FACING,
            risk_score=0.9,
            vulnerability_count=8,
        )
        results = eng.prioritize_remediation()
        assert results[0]["component_id"] == "high"
        assert results[0]["priority_score"] > results[1]["priority_score"]

    def test_empty(self):
        eng = AttackSurfaceContinuousScorerEngine()
        assert eng.prioritize_remediation() == []


# =========================================================================
# IncidentAutoClassificationEngine
# =========================================================================


class TestIncidentEnums:
    def test_class_malware(self):
        assert IncidentClass.MALWARE == "malware"

    def test_class_phishing(self):
        assert IncidentClass.PHISHING == "phishing"

    def test_class_ddos(self):
        assert IncidentClass.DDOS == "ddos"

    def test_class_breach(self):
        assert IncidentClass.DATA_BREACH == "data_breach"

    def test_method_rule(self):
        assert ClassificationMethod.RULE_BASED == "rule_based"

    def test_method_hybrid(self):
        assert ClassificationMethod.HYBRID == "hybrid"

    def test_confidence_definitive(self):
        assert ClassificationConfidence.DEFINITIVE == "definitive"

    def test_confidence_unknown(self):
        assert ClassificationConfidence.UNKNOWN == "unknown"


class TestIncidentModels:
    def test_record_defaults(self):
        r = IncidentClassificationRecord()
        assert r.id
        assert r.incident_class == IncidentClass.MALWARE

    def test_analysis_defaults(self):
        a = IncidentClassificationAnalysis()
        assert a.id
        assert a.confidence_score == 0.0

    def test_report_defaults(self):
        rpt = IncidentClassificationReport()
        assert rpt.total_records == 0
        assert rpt.accuracy_rate == 0.0


class TestIncidentAddRecord:
    def test_basic(self):
        eng = IncidentAutoClassificationEngine()
        rec = eng.add_record(
            incident_id="inc-1",
            incident_class=IncidentClass.PHISHING,
            severity=0.7,
        )
        assert rec.incident_id == "inc-1"
        assert rec.incident_class == IncidentClass.PHISHING

    def test_eviction(self):
        eng = IncidentAutoClassificationEngine(max_records=3)
        for i in range(5):
            eng.add_record(incident_id=f"i-{i}")
        assert len(eng._records) == 3


class TestIncidentProcess:
    def test_definitive(self):
        eng = IncidentAutoClassificationEngine()
        rec = eng.add_record(
            incident_id="inc-1",
            severity=0.8,
            indicators=["a", "b", "c", "d", "e"],
        )
        result = eng.process(rec.id)
        assert isinstance(result, IncidentClassificationAnalysis)
        assert result.classification_confidence == (
            ClassificationConfidence.DEFINITIVE
        )

    def test_possible(self):
        eng = IncidentAutoClassificationEngine()
        rec = eng.add_record(
            incident_id="inc-2",
            severity=0.2,
            indicators=["x"],
        )
        result = eng.process(rec.id)
        assert isinstance(result, IncidentClassificationAnalysis)
        assert result.classification_confidence == (
            ClassificationConfidence.POSSIBLE
        )

    def test_unknown(self):
        eng = IncidentAutoClassificationEngine()
        rec = eng.add_record(incident_id="inc-3")
        result = eng.process(rec.id)
        assert result.classification_confidence == (
            ClassificationConfidence.UNKNOWN
        )

    def test_not_found(self):
        eng = IncidentAutoClassificationEngine()
        result = eng.process("missing")
        assert result["status"] == "not_found"


class TestIncidentReport:
    def test_populated(self):
        eng = IncidentAutoClassificationEngine()
        eng.add_record(
            incident_id="i1",
            incident_class=IncidentClass.MALWARE,
            was_correct=True,
        )
        eng.add_record(
            incident_id="i2",
            incident_class=IncidentClass.PHISHING,
            was_correct=False,
        )
        rpt = eng.generate_report()
        assert isinstance(rpt, IncidentClassificationReport)
        assert rpt.total_records == 2
        assert rpt.accuracy_rate == 50.0

    def test_empty(self):
        eng = IncidentAutoClassificationEngine()
        rpt = eng.generate_report()
        assert len(rpt.recommendations) > 0


class TestIncidentStatsAndClear:
    def test_stats(self):
        eng = IncidentAutoClassificationEngine()
        eng.add_record(incident_id="i1")
        assert eng.get_stats()["total_records"] == 1

    def test_clear(self):
        eng = IncidentAutoClassificationEngine()
        eng.add_record(incident_id="i1")
        assert eng.clear_data() == {"status": "cleared"}
        assert len(eng._records) == 0


class TestClassifyIncident:
    def test_malware_indicators(self):
        eng = IncidentAutoClassificationEngine()
        result = eng.classify_incident(
            indicators=["ransomware", "c2", "payload"],
        )
        assert result["predicted_class"] == "malware"
        assert result["confidence"] == "definitive"

    def test_phishing_indicators(self):
        eng = IncidentAutoClassificationEngine()
        result = eng.classify_incident(
            indicators=["email", "credential_harvest"],
        )
        assert result["predicted_class"] == "phishing"
        assert result["confidence"] == "probable"

    def test_no_indicators(self):
        eng = IncidentAutoClassificationEngine()
        result = eng.classify_incident(indicators=[])
        assert result["confidence"] == "unknown"

    def test_ddos_indicators(self):
        eng = IncidentAutoClassificationEngine()
        result = eng.classify_incident(
            indicators=["ddos", "flood", "syn_flood"],
        )
        assert result["predicted_class"] == "ddos"


class TestMeasureClassificationAccuracy:
    def test_with_data(self):
        eng = IncidentAutoClassificationEngine()
        eng.add_record(
            incident_class=IncidentClass.MALWARE, was_correct=True,
        )
        eng.add_record(
            incident_class=IncidentClass.MALWARE, was_correct=True,
        )
        eng.add_record(
            incident_class=IncidentClass.PHISHING, was_correct=False,
        )
        result = eng.measure_classification_accuracy()
        assert result["overall_accuracy"] == 66.67
        assert result["grade"] == "fair"

    def test_empty(self):
        eng = IncidentAutoClassificationEngine()
        result = eng.measure_classification_accuracy()
        assert result["grade"] == "no_data"

    def test_excellent(self):
        eng = IncidentAutoClassificationEngine()
        for _ in range(10):
            eng.add_record(was_correct=True)
        result = eng.measure_classification_accuracy()
        assert result["grade"] == "excellent"


class TestIdentifyMisclassified:
    def test_verified_incorrect(self):
        eng = IncidentAutoClassificationEngine()
        eng.add_record(
            incident_id="i1",
            incident_class=IncidentClass.MALWARE,
            was_correct=False,
            severity=0.8,
        )
        results = eng.identify_misclassified_incidents()
        assert len(results) == 1
        assert results[0]["reason"] == "verified_incorrect"

    def test_low_confidence_high_severity(self):
        eng = IncidentAutoClassificationEngine()
        eng.add_record(
            incident_id="i2",
            classification_confidence=ClassificationConfidence.UNKNOWN,
            severity=0.7,
        )
        results = eng.identify_misclassified_incidents()
        assert len(results) == 1
        assert results[0]["reason"] == "low_confidence_high_severity"

    def test_class_mismatch(self):
        eng = IncidentAutoClassificationEngine()
        eng.add_record(
            incident_id="i3",
            incident_class=IncidentClass.MALWARE,
            actual_class="phishing",
        )
        results = eng.identify_misclassified_incidents()
        assert len(results) == 1
        assert results[0]["reason"] == "class_mismatch"

    def test_no_issues(self):
        eng = IncidentAutoClassificationEngine()
        eng.add_record(
            incident_id="i4",
            was_correct=True,
            classification_confidence=ClassificationConfidence.DEFINITIVE,
        )
        results = eng.identify_misclassified_incidents()
        assert len(results) == 0
