"""Tests for shieldops.security.threat_object_correlator_engine."""

from __future__ import annotations

from shieldops.security.threat_object_correlator_engine import (
    CampaignConfidence,
    CorrelationStrength,
    ThreatObjectAnalysis,
    ThreatObjectCorrelatorEngine,
    ThreatObjectRecord,
    ThreatObjectReport,
    ThreatObjectType,
)


def _engine(**kw) -> ThreatObjectCorrelatorEngine:
    return ThreatObjectCorrelatorEngine(**kw)


# --- Enums ---


class TestEnums:
    def test_type_ip(self):
        assert ThreatObjectType.IP_ADDRESS == "ip_address"

    def test_type_domain(self):
        assert ThreatObjectType.DOMAIN == "domain"

    def test_type_hash(self):
        assert ThreatObjectType.FILE_HASH == "file_hash"

    def test_type_url(self):
        assert ThreatObjectType.URL == "url"

    def test_strength_strong(self):
        assert CorrelationStrength.STRONG == "strong"

    def test_strength_coincidental(self):
        assert CorrelationStrength.COINCIDENTAL == "coincidental"

    def test_confidence_confirmed(self):
        assert CampaignConfidence.CONFIRMED == "confirmed"

    def test_confidence_speculative(self):
        assert CampaignConfidence.SPECULATIVE == "speculative"


# --- Models ---


class TestModels:
    def test_record_defaults(self):
        r = ThreatObjectRecord()
        assert r.id
        assert r.object_value == ""
        assert r.threat_score == 0.0

    def test_analysis_defaults(self):
        a = ThreatObjectAnalysis()
        assert a.relevance_score == 0.0
        assert a.campaign_linked is False

    def test_report_defaults(self):
        r = ThreatObjectReport()
        assert r.total_records == 0
        assert r.top_threat_objects == []


# --- add_record ---


class TestAddRecord:
    def test_basic(self):
        eng = _engine()
        r = eng.add_record(
            object_value="192.168.1.1",
            object_type=ThreatObjectType.IP_ADDRESS,
            threat_score=80.0,
        )
        assert r.object_value == "192.168.1.1"
        assert r.threat_score == 80.0

    def test_eviction(self):
        eng = _engine(max_records=2)
        for i in range(5):
            eng.add_record(object_value=f"obj-{i}")
        assert len(eng._records) == 2


# --- process ---


class TestProcess:
    def test_strong_relevance(self):
        eng = _engine()
        r = eng.add_record(
            object_value="bad.com",
            correlation_strength=CorrelationStrength.STRONG,
            threat_score=100.0,
        )
        result = eng.process(r.id)
        assert isinstance(result, ThreatObjectAnalysis)
        assert result.relevance_score == 100.0

    def test_campaign_linked(self):
        eng = _engine()
        r = eng.add_record(
            object_value="evil.com",
            campaign_confidence=CampaignConfidence.CONFIRMED,
            threat_score=60.0,
        )
        result = eng.process(r.id)
        assert result.campaign_linked is True

    def test_speculative_not_linked(self):
        eng = _engine()
        r = eng.add_record(
            object_value="maybe.com",
            campaign_confidence=CampaignConfidence.SPECULATIVE,
        )
        result = eng.process(r.id)
        assert result.campaign_linked is False

    def test_not_found(self):
        eng = _engine()
        result = eng.process("ghost")
        assert result["status"] == "not_found"


# --- generate_report ---


class TestGenerateReport:
    def test_with_data(self):
        eng = _engine()
        eng.add_record(
            object_value="192.168.0.1",
            object_type=ThreatObjectType.IP_ADDRESS,
            correlation_strength=CorrelationStrength.STRONG,
        )
        report = eng.generate_report()
        assert report.total_records == 1
        assert "ip_address" in report.by_object_type

    def test_empty(self):
        eng = _engine()
        report = eng.generate_report()
        assert "No strongly" in report.recommendations[0]


# --- get_stats / clear ---


class TestGetStatsAndClear:
    def test_stats_populated(self):
        eng = _engine()
        eng.add_record(object_type=ThreatObjectType.DOMAIN)
        stats = eng.get_stats()
        assert stats["total_records"] == 1
        assert "domain" in stats["object_type_distribution"]

    def test_clear(self):
        eng = _engine()
        eng.add_record()
        eng.clear_data()
        assert len(eng._records) == 0


# --- domain methods ---


class TestCorrelateThreatObjects:
    def test_by_campaign(self):
        eng = _engine()
        eng.add_record(object_value="ip1", campaign_id="C-001", threat_score=70.0)
        eng.add_record(object_value="dom1", campaign_id="C-001", threat_score=80.0)
        results = eng.correlate_threat_objects()
        assert len(results) == 1
        assert results[0]["campaign_id"] == "C-001"
        assert results[0]["object_count"] == 2

    def test_empty(self):
        eng = _engine()
        assert eng.correlate_threat_objects() == []


class TestDetectCampaignIndicators:
    def test_multi_campaign(self):
        eng = _engine()
        eng.add_record(object_value="bad.com", campaign_id="C-001")
        eng.add_record(object_value="bad.com", campaign_id="C-002")
        results = eng.detect_campaign_indicators()
        assert results[0]["object_value"] == "bad.com"
        assert results[0]["multi_campaign"] is True

    def test_empty(self):
        eng = _engine()
        assert eng.detect_campaign_indicators() == []


class TestScoreObjectThreatRelevance:
    def test_confirmed_strong(self):
        eng = _engine()
        eng.add_record(
            object_value="evil.com",
            correlation_strength=CorrelationStrength.STRONG,
            campaign_confidence=CampaignConfidence.CONFIRMED,
            threat_score=100.0,
        )
        results = eng.score_object_threat_relevance()
        assert results[0]["relevance_score"] == 100.0

    def test_speculative_coincidental(self):
        eng = _engine()
        eng.add_record(
            object_value="maybe.com",
            correlation_strength=CorrelationStrength.COINCIDENTAL,
            campaign_confidence=CampaignConfidence.SPECULATIVE,
            threat_score=100.0,
        )
        results = eng.score_object_threat_relevance()
        assert results[0]["relevance_score"] == round(100.0 * 0.1 * 0.2, 4)
