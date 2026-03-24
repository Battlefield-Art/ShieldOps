"""Tests for ShadowAIDiscovery engine."""

import pytest

from shieldops.security.shadow_ai_discovery import (
    AIProvider,
    ShadowAIDiscovery,
    ShadowAIReport,
    ShadowAISource,
    ShadowAIStatus,
)


@pytest.fixture
def engine():
    return ShadowAIDiscovery(max_records=100, threshold=50.0)


def test_record_detection(engine):
    rec = engine.record_detection(
        provider=AIProvider.OPENAI,
        api_endpoint="api.openai.com",
        calling_service="backend-svc",
        detection_source=ShadowAISource.NETWORK_TRAFFIC,
        request_count=100,
    )
    assert rec.provider == AIProvider.OPENAI
    assert rec.calling_service == "backend-svc"
    assert rec.request_count == 100
    assert len(engine._records) == 1


def test_record_detection_dedup(engine):
    engine.record_detection(
        provider=AIProvider.OPENAI,
        api_endpoint="api.openai.com",
        calling_service="backend-svc",
        request_count=50,
    )
    engine.record_detection(
        provider=AIProvider.OPENAI,
        api_endpoint="api.openai.com",
        calling_service="backend-svc",
        request_count=30,
    )
    assert len(engine._records) == 1
    assert engine._records[0].request_count == 80


def test_analyze_network_patterns(engine):
    dns_logs = [
        {"domain": "api.openai.com", "source_service": "ml-pipeline", "count": 200},
        {"domain": "api.anthropic.com", "source_service": "chatbot", "count": 50},
        {"domain": "google.com", "source_service": "crawler", "count": 1000},
    ]
    detections = engine.analyze_network_patterns(dns_logs=dns_logs)
    assert len(detections) == 2
    providers = {d.provider for d in detections}
    assert AIProvider.OPENAI in providers
    assert AIProvider.ANTHROPIC in providers


def test_analyze_billing_anomalies(engine):
    billing = [
        {"service": "openai-api-charges", "cost": 120.0, "project": "secret-project"},
    ]
    detections = engine.analyze_billing_anomalies(cloud_billing_data=billing)
    assert len(detections) == 1
    assert detections[0].provider == AIProvider.OPENAI


def test_analyze_billing_no_ai(engine):
    billing = [{"service": "s3-storage", "cost": 50.0, "project": "data-lake"}]
    detections = engine.analyze_billing_anomalies(cloud_billing_data=billing)
    assert len(detections) == 0


def test_correlate_with_registry(engine):
    engine.record_detection(
        provider=AIProvider.OPENAI,
        api_endpoint="api.openai.com",
        calling_service="unregistered-svc",
    )

    class MockRegistry:
        def search(self, query=""):
            return []  # nothing registered

    unregistered = engine.correlate_with_registry(MockRegistry())
    assert len(unregistered) == 1
    assert unregistered[0]["status"] == "unregistered"


def test_correlate_with_registry_registered(engine):
    engine.record_detection(
        provider=AIProvider.OPENAI,
        api_endpoint="api.openai.com",
        calling_service="known-svc",
    )
    engine._records[0].status = ShadowAIStatus.REGISTERED

    class MockRegistry:
        def search(self, query=""):
            return [{"name": "known-svc"}]

    unregistered = engine.correlate_with_registry(MockRegistry())
    assert len(unregistered) == 0


def test_generate_report(engine):
    engine.record_detection(
        provider=AIProvider.OPENAI, api_endpoint="api.openai.com", calling_service="svc-1"
    )
    report = engine.generate_report()
    assert isinstance(report, ShadowAIReport)
    assert report.total_records == 1
    assert report.gap_count >= 1


def test_get_stats(engine):
    engine.record_detection(
        provider=AIProvider.ANTHROPIC,
        api_endpoint="api.anthropic.com",
        calling_service="svc-1",
        request_count=10,
    )
    stats = engine.get_stats()
    assert "total_records" in stats
    assert "total_indicators" in stats
    assert "provider_distribution" in stats
    assert "unique_services" in stats
    assert "total_estimated_monthly_cost" in stats


def test_clear_data(engine):
    engine.record_detection(provider=AIProvider.OPENAI, calling_service="svc-1")
    engine.add_indicator(pattern="openai", confidence=0.9)
    engine.clear_data()
    assert len(engine._records) == 0
    assert len(engine._indicators) == 0
