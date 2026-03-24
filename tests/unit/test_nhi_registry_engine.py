"""Tests for NHIRegistryEngine."""

import time

import pytest

from shieldops.security.nhi_registry_engine import (
    NHIRegistryEngine,
    NHIRegistryReport,
    NHIType,
)


@pytest.fixture
def engine():
    return NHIRegistryEngine(max_records=100, threshold=50.0)


def test_register_identity(engine):
    rec = engine.register_identity(
        name="deploy-bot",
        nhi_type=NHIType.AI_AGENT,
        provider="aws",
        permissions=["ec2:Describe*"],
        owner="platform-team",
    )
    assert rec.name == "deploy-bot"
    assert rec.nhi_type == NHIType.AI_AGENT
    assert rec.provider == "aws"
    assert len(engine._records) == 1


def test_classify_identity(engine):
    rec = engine.register_identity("svc-account", provider="gcp")
    classification = engine.classify_identity(
        nhi_id=rec.id,
        classification_reason="CI/CD service account",
        confidence=0.95,
        classifier="auto",
    )
    assert classification.nhi_id == rec.id
    assert classification.confidence == 0.95
    assert len(engine._classifications) == 1


def test_detect_orphaned(engine):
    rec = engine.register_identity("orphan-bot", owner="")
    orphaned = engine.detect_orphaned()
    assert len(orphaned) >= 1
    assert any(r.id == rec.id for r in orphaned)


def test_detect_orphaned_with_owner(engine):
    engine.register_identity("owned-bot", owner="team-a", last_used=time.time())
    orphaned = engine.detect_orphaned(stale_days=90)
    # Should not be flagged (has owner and recent activity)
    assert len(orphaned) == 0


def test_detect_over_privileged(engine):
    rec = engine.register_identity(
        "super-admin",
        permissions=["*:*", "iam:*", "s3:*"] + [f"perm-{i}" for i in range(10)],
        owner="ops",
    )
    over_priv = engine.detect_over_privileged(max_permissions=10)
    assert len(over_priv) >= 1
    assert any(r.id == rec.id for r in over_priv)


def test_detect_over_privileged_clean(engine):
    engine.register_identity("minimal-bot", permissions=["s3:GetObject"], owner="ops")
    over_priv = engine.detect_over_privileged(max_permissions=10)
    assert len(over_priv) == 0


def test_calculate_risk_score(engine):
    rec = engine.register_identity(
        "risky-bot",
        nhi_type=NHIType.MCP_CONNECTION,
        permissions=["*:*"],
        owner="",
    )
    score = engine.calculate_risk_score(rec.id)
    assert score > 0
    assert score <= 100.0


def test_search(engine):
    engine.register_identity("aws-bot", nhi_type=NHIType.AI_AGENT, provider="aws")
    engine.register_identity("gcp-svc", nhi_type=NHIType.SERVICE_ACCOUNT, provider="gcp")
    results = engine.search(nhi_type=NHIType.AI_AGENT)
    assert len(results) == 1
    assert results[0].name == "aws-bot"

    results_prov = engine.search(provider="gcp")
    assert len(results_prov) == 1


def test_generate_report(engine):
    engine.register_identity("bot-1", nhi_type=NHIType.AI_AGENT, provider="aws", owner="team")
    report = engine.generate_report()
    assert isinstance(report, NHIRegistryReport)
    assert report.total_records == 1


def test_get_stats(engine):
    engine.register_identity("bot-1", provider="aws", owner="team")
    stats = engine.get_stats()
    assert "total_records" in stats
    assert "total_classifications" in stats
    assert "threshold" in stats
    assert "nhi_type_distribution" in stats
    assert "unique_providers" in stats


def test_clear_data(engine):
    engine.register_identity("bot-1")
    engine.classify_identity("dummy-id", classification_reason="test")
    engine.clear_data()
    assert len(engine._records) == 0
    assert len(engine._classifications) == 0
