"""End-to-end integration tests for the Threat Intel Agent.

Tests the full LangGraph workflow: collect -> correlate -> assess -> distribute,
with mock feed clients (no real SIEM/firewall/EDR needed). The toolkit uses
fallback paths that produce deterministic output when no clients are injected.
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from shieldops.agents.threat_intel.models import (
    IntelSource,
    ThreatConfidence,
    ThreatIntelState,
)
from shieldops.agents.threat_intel.prompts import AssessmentResult
from shieldops.agents.threat_intel.runner import ThreatIntelRunner


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def mock_osint_feed():
    """OSINT feed returning high-confidence indicators."""
    client = AsyncMock()
    client.fetch_indicators.return_value = [
        {
            "value": "198.51.100.42",
            "type": "ip",
            "confidence": "confirmed",
            "tags": ["c2", "botnet"],
            "mitre_tactics": ["TA0011"],
            "first_seen": datetime.now(UTC),
            "last_seen": datetime.now(UTC),
        },
        {
            "value": "evil-domain.example.com",
            "type": "domain",
            "confidence": "probable",
            "tags": ["phishing"],
            "mitre_tactics": ["TA0001"],
            "first_seen": datetime.now(UTC),
            "last_seen": datetime.now(UTC),
        },
    ]
    return client


@pytest.fixture
def mock_internal_feed():
    """Internal feed returning unverified indicators."""
    client = AsyncMock()
    client.fetch_indicators.return_value = [
        {
            "value": "abc123def456",
            "type": "hash",
            "confidence": "unverified",
            "tags": ["malware-candidate"],
            "mitre_tactics": [],
            "first_seen": datetime.now(UTC),
            "last_seen": datetime.now(UTC),
        },
    ]
    return client


@pytest.fixture
def mock_siem_client():
    """SIEM that returns matches for some indicators."""
    client = AsyncMock()

    async def _search(value, indicator_type="ip"):
        if value == "198.51.100.42":
            return {
                "matches": [
                    {"event_id": "ev-001", "source": "firewall", "action": "allow"},
                    {"event_id": "ev-002", "source": "proxy", "action": "connect"},
                ],
                "entities": ["web-server-1", "proxy-01"],
            }
        return {"matches": [], "entities": []}

    client.search.side_effect = _search
    client.ingest_indicators = AsyncMock(return_value={"ingested": True})
    return client


@pytest.fixture
def mock_firewall_client():
    """Firewall client that accepts IOC distribution."""
    client = AsyncMock()
    client.ingest_indicators.return_value = {"rules_created": 2}
    return client


@pytest.fixture
def assessment_llm_response():
    """Deterministic LLM response for the assessment node."""
    return AssessmentResult(
        summary="Active C2 infrastructure detected with internal matches",
        actionable_count=2,
        top_threats=["C2 IP with confirmed botnet activity"],
        recommended_actions=["Block IP at firewall", "Investigate matched hosts"],
        overall_risk="high",
    )


# ── Full Pipeline ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_threat_intel_full_pipeline(
    mock_osint_feed,
    mock_internal_feed,
    mock_siem_client,
    mock_firewall_client,
    assessment_llm_response,
):
    """Full pipeline collects, correlates, assesses, and distributes."""

    async def fake_llm(system_prompt="", user_prompt="", schema=None, **kwargs):
        return assessment_llm_response

    with patch(
        "shieldops.agents.threat_intel.nodes.llm_structured",
        side_effect=fake_llm,
    ):
        runner = ThreatIntelRunner(
            feed_clients={
                "osint": mock_osint_feed,
                "internal": mock_internal_feed,
            },
            siem_client=mock_siem_client,
            firewall_client=mock_firewall_client,
        )
        result = await runner.run(
            sources=[IntelSource.OSINT, IntelSource.INTERNAL],
            distribution_channels=["siem", "firewall"],
        )

    assert isinstance(result, ThreatIntelState)
    assert result.error is None
    assert len(result.indicators_collected) == 3
    assert len(result.correlations) == 3
    assert len(result.assessments) == 3
    assert result.high_priority_count >= 1
    assert result.confidence_score > 0
    assert len(result.reasoning_chain) >= 3
    assert result.current_step == "complete"


@pytest.mark.asyncio
async def test_threat_intel_no_backends():
    """Pipeline runs with no feeds, SIEM, or firewall and degrades gracefully."""
    runner = ThreatIntelRunner()
    result = await runner.run(sources=[IntelSource.OSINT])

    assert isinstance(result, ThreatIntelState)
    assert result.error is None
    # No feeds configured = no indicators collected
    assert len(result.indicators_collected) == 0
    assert len(result.reasoning_chain) >= 2


# ── Collection ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_threat_intel_collects_from_multiple_sources(
    mock_osint_feed,
    mock_internal_feed,
):
    """Collection merges indicators from OSINT and internal feeds."""
    runner = ThreatIntelRunner(
        feed_clients={
            "osint": mock_osint_feed,
            "internal": mock_internal_feed,
        },
    )
    result = await runner.run(
        sources=[IntelSource.OSINT, IntelSource.INTERNAL],
    )

    assert len(result.indicators_collected) == 3
    sources_present = {ind.source for ind in result.indicators_collected}
    assert IntelSource.OSINT in sources_present
    assert IntelSource.INTERNAL in sources_present


@pytest.mark.asyncio
async def test_threat_intel_collection_handles_feed_error():
    """Collection continues when one feed raises an exception."""
    broken_feed = AsyncMock()
    broken_feed.fetch_indicators.side_effect = ConnectionError("Feed unreachable")

    runner = ThreatIntelRunner(
        feed_clients={"osint": broken_feed},
    )
    result = await runner.run(sources=[IntelSource.OSINT])

    # Should not error out; just no indicators
    assert result.error is None
    assert len(result.indicators_collected) == 0


# ── Correlation ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_threat_intel_correlates_against_siem(
    mock_osint_feed,
    mock_siem_client,
):
    """Indicators with SIEM matches produce correlations with match_count > 0."""
    runner = ThreatIntelRunner(
        feed_clients={"osint": mock_osint_feed},
        siem_client=mock_siem_client,
    )
    result = await runner.run(sources=[IntelSource.OSINT])

    ip_corr = next(
        (c for c in result.correlations if c.indicator_value == "198.51.100.42"),
        None,
    )
    assert ip_corr is not None
    assert ip_corr.match_count == 2
    assert "web-server-1" in ip_corr.entities_affected


# ── Assessment ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_threat_intel_high_confidence_indicators_are_actionable(
    mock_osint_feed,
    mock_siem_client,
):
    """Confirmed/probable indicators with matches score high relevance."""
    runner = ThreatIntelRunner(
        feed_clients={"osint": mock_osint_feed},
        siem_client=mock_siem_client,
    )
    result = await runner.run(sources=[IntelSource.OSINT])

    ip_assessment = next(
        (a for a in result.assessments if a.indicator_value == "198.51.100.42"),
        None,
    )
    assert ip_assessment is not None
    # confirmed (0.9) + match_boost (2 * 0.1 = 0.2) + mitre_boost (0.1) = 1.0 capped
    assert ip_assessment.relevance_score >= 0.8
    assert ip_assessment.actionable is True
    assert len(ip_assessment.recommended_actions) >= 1


@pytest.mark.asyncio
async def test_threat_intel_unverified_indicators_not_actionable(
    mock_internal_feed,
):
    """Unverified indicators with no matches score low relevance."""
    runner = ThreatIntelRunner(
        feed_clients={"internal": mock_internal_feed},
    )
    result = await runner.run(sources=[IntelSource.INTERNAL])

    hash_assessment = next(
        (a for a in result.assessments if a.indicator_value == "abc123def456"),
        None,
    )
    assert hash_assessment is not None
    # unverified (0.1) + no matches + no mitre = 0.1
    assert hash_assessment.relevance_score < 0.5
    assert hash_assessment.actionable is False


# ── Conditional Routing ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_threat_intel_distributes_when_high_priority(
    mock_osint_feed,
    mock_siem_client,
    mock_firewall_client,
):
    """Distribution node is reached when high_priority_count > 0."""
    runner = ThreatIntelRunner(
        feed_clients={"osint": mock_osint_feed},
        siem_client=mock_siem_client,
        firewall_client=mock_firewall_client,
    )
    result = await runner.run(
        sources=[IntelSource.OSINT],
        distribution_channels=["firewall"],
    )

    assert result.high_priority_count >= 1
    assert result.current_step == "complete"
    assert "firewall" in result.distribution_results


@pytest.mark.asyncio
async def test_threat_intel_skips_distribution_when_no_priority(
    mock_internal_feed,
):
    """Distribution is skipped when no high-priority or actionable indicators."""
    runner = ThreatIntelRunner(
        feed_clients={"internal": mock_internal_feed},
    )
    result = await runner.run(sources=[IntelSource.INTERNAL])

    # Unverified hash with no matches: not actionable, no high priority
    assert result.high_priority_count == 0
    # Distribution should be skipped
    assert result.current_step == "assess_threats"
    assert result.distribution_results == {}


# ── Result Storage ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_threat_intel_stores_result_in_memory(mock_osint_feed):
    """Runner stores completed run in its internal results dict."""
    runner = ThreatIntelRunner(
        feed_clients={"osint": mock_osint_feed},
    )
    result = await runner.run(sources=[IntelSource.OSINT])

    listed = runner.list_results()
    assert len(listed) == 1
    assert listed[0]["request_id"] == result.request_id
    assert listed[0]["indicators"] == len(result.indicators_collected)

    retrieved = runner.get_result(result.request_id)
    assert retrieved is not None
    assert retrieved.request_id == result.request_id
