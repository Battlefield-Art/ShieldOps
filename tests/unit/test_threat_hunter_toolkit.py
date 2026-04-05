"""Tests for the Threat Hunter Agent toolkit (tools.py)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from shieldops.agents.threat_hunter.tools import ThreatHunterToolkit

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_crowdstrike() -> AsyncMock:
    """Create a mock CrowdStrike connector."""
    cs = AsyncMock()
    cs.query_iocs = AsyncMock(
        return_value=[
            {
                "id": "ioc-001",
                "type": "ipv4",
                "value": "10.0.0.99",
                "severity": "high",
                "action": "detect",
            }
        ]
    )
    cs.get_threat_graph = AsyncMock(return_value={"resources": [{"id": "tg-1"}]})
    cs.get_detections = AsyncMock(
        return_value=[
            {
                "detection_id": "det-001",
                "max_severity_displayname": "High",
                "tactic": "Lateral Movement",
                "technique": "T1021",
                "device": {"hostname": "srv-prod-01"},
            },
        ]
    )
    return cs


@pytest.fixture
def mock_splunk() -> AsyncMock:
    """Create a mock Splunk connector."""
    sp = AsyncMock()
    sp.search_spl = AsyncMock(
        return_value=[
            {
                "src_ip": "10.0.0.99",
                "user": "admin",
                "count": "42",
                "sourcetype": "WinEventLog:Security",
                "index": "security",
                "source": "WinEventLog",
            }
        ]
    )
    return sp


@pytest.fixture
def toolkit_with_connectors(
    mock_crowdstrike: AsyncMock, mock_splunk: AsyncMock
) -> ThreatHunterToolkit:
    """Toolkit initialized with mocked connectors."""
    return ThreatHunterToolkit(
        connector_router={"crowdstrike": mock_crowdstrike, "splunk": mock_splunk},
    )


@pytest.fixture
def toolkit_no_connectors() -> ThreatHunterToolkit:
    """Toolkit without any connectors (heuristic fallback)."""
    return ThreatHunterToolkit()


# ---------------------------------------------------------------------------
# generate_hypothesis
# ---------------------------------------------------------------------------


class TestGenerateHypothesis:
    @pytest.mark.asyncio
    async def test_returns_non_empty_hypothesis(
        self, toolkit_with_connectors: ThreatHunterToolkit
    ) -> None:
        context = {
            "hypothesis": "Adversary using lateral movement via RDP",
            "hunt_scope": {"indicators": ["10.0.0.99"]},
        }
        result = await toolkit_with_connectors.generate_hypothesis(context)
        assert result["hypothesis"]
        assert isinstance(result["data_sources"], list)
        assert len(result["data_sources"]) > 0
        assert isinstance(result["confidence"], float)
        assert 0.0 < result["confidence"] <= 1.0

    @pytest.mark.asyncio
    async def test_maps_mitre_techniques(
        self, toolkit_with_connectors: ThreatHunterToolkit
    ) -> None:
        context = {
            "hypothesis": "Brute force credential attack via RDP lateral movement",
            "hunt_scope": {},
        }
        result = await toolkit_with_connectors.generate_hypothesis(context)
        assert len(result["mitre_techniques"]) > 0
        # Should contain brute force and/or lateral movement techniques
        techniques = result["mitre_techniques"]
        assert any(t in techniques for t in ["T1110", "T1021", "T1021.001"])

    @pytest.mark.asyncio
    async def test_empty_hypothesis_returns_default(
        self, toolkit_no_connectors: ThreatHunterToolkit
    ) -> None:
        result = await toolkit_no_connectors.generate_hypothesis({})
        assert result["hypothesis"]  # should have a default
        assert result["data_sources"]
        assert result["confidence"] > 0

    @pytest.mark.asyncio
    async def test_enriches_with_threat_graph(
        self, toolkit_with_connectors: ThreatHunterToolkit, mock_crowdstrike: AsyncMock
    ) -> None:
        context = {
            "hypothesis": "Suspicious lateral movement",
            "hunt_scope": {"indicators": ["192.168.1.1"]},
        }
        await toolkit_with_connectors.generate_hypothesis(context)
        mock_crowdstrike.get_threat_graph.assert_called()


# ---------------------------------------------------------------------------
# sweep_iocs
# ---------------------------------------------------------------------------


class TestSweepIocs:
    @pytest.mark.asyncio
    async def test_queries_crowdstrike_iocs(
        self, toolkit_with_connectors: ThreatHunterToolkit, mock_crowdstrike: AsyncMock
    ) -> None:
        scope = {"time_range": "7d"}
        indicators = ["10.0.0.99", "evil.example.com"]
        results = await toolkit_with_connectors.sweep_iocs(scope, indicators)

        assert len(results) > 0
        cs_results = [r for r in results if r["source"] == "crowdstrike"]
        assert len(cs_results) > 0
        assert cs_results[0]["indicator"] in indicators
        mock_crowdstrike.query_iocs.assert_called()

    @pytest.mark.asyncio
    async def test_queries_splunk_logs(
        self, toolkit_with_connectors: ThreatHunterToolkit, mock_splunk: AsyncMock
    ) -> None:
        scope = {"time_range": "24h"}
        indicators = ["10.0.0.99"]
        results = await toolkit_with_connectors.sweep_iocs(scope, indicators)

        splunk_results = [r for r in results if r["source"] == "splunk"]
        assert len(splunk_results) > 0
        mock_splunk.search_spl.assert_called()

    @pytest.mark.asyncio
    async def test_heuristic_fallback(self, toolkit_no_connectors: ThreatHunterToolkit) -> None:
        scope = {"time_range": "7d"}
        indicators = ["10.0.0.1", "malware.example.com"]
        results = await toolkit_no_connectors.sweep_iocs(scope, indicators)

        assert len(results) > 0
        assert all(r["source"] == "heuristic" for r in results)

    @pytest.mark.asyncio
    async def test_classifies_ioc_types(self, toolkit_no_connectors: ThreatHunterToolkit) -> None:
        scope = {}
        indicators = [
            "192.168.1.1",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "evil.example.com",
        ]
        results = await toolkit_no_connectors.sweep_iocs(scope, indicators)

        type_map = {r["indicator"]: r["ioc_type"] for r in results}
        assert type_map["192.168.1.1"] == "ipv4"
        assert (
            type_map["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"] == "sha256"
        )
        assert type_map["evil.example.com"] == "domain"

    @pytest.mark.asyncio
    async def test_empty_indicators(self, toolkit_with_connectors: ThreatHunterToolkit) -> None:
        results = await toolkit_with_connectors.sweep_iocs({}, [])
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# analyze_behavior
# ---------------------------------------------------------------------------


class TestAnalyzeBehavior:
    @pytest.mark.asyncio
    async def test_runs_splunk_queries(
        self, toolkit_with_connectors: ThreatHunterToolkit, mock_splunk: AsyncMock
    ) -> None:
        scope = {
            "time_range": "7d",
            "environments": ["production"],
            "mitre_techniques": ["T1110"],
        }
        findings = await toolkit_with_connectors.analyze_behavior(scope, "baseline-1")

        assert len(findings) > 0
        splunk_findings = [f for f in findings if f["source"] == "splunk"]
        assert len(splunk_findings) > 0
        assert splunk_findings[0]["analysis_type"] == "anomalous_auth"
        mock_splunk.search_spl.assert_called()

    @pytest.mark.asyncio
    async def test_checks_crowdstrike_detections(
        self, toolkit_with_connectors: ThreatHunterToolkit, mock_crowdstrike: AsyncMock
    ) -> None:
        scope = {
            "time_range": "7d",
            "environments": ["production"],
        }
        findings = await toolkit_with_connectors.analyze_behavior(scope, "default")

        cs_findings = [f for f in findings if f["source"] == "crowdstrike"]
        assert len(cs_findings) > 0
        assert cs_findings[0]["analysis_type"] == "endpoint_detections"
        mock_crowdstrike.get_detections.assert_called()

    @pytest.mark.asyncio
    async def test_heuristic_fallback(self, toolkit_no_connectors: ThreatHunterToolkit) -> None:
        scope = {"time_range": "7d", "mitre_techniques": ["T1110"]}
        findings = await toolkit_no_connectors.analyze_behavior(scope, "default")

        assert len(findings) > 0
        assert all(f["source"] == "heuristic" for f in findings)

    @pytest.mark.asyncio
    async def test_severity_assessment(self, toolkit_with_connectors: ThreatHunterToolkit) -> None:
        scope = {"time_range": "7d", "mitre_techniques": ["T1021"]}
        findings = await toolkit_with_connectors.analyze_behavior(scope, "default")

        for finding in findings:
            assert finding["severity"] in ("critical", "high", "medium", "low")


# ---------------------------------------------------------------------------
# check_mitre_coverage
# ---------------------------------------------------------------------------


class TestCheckMitreCoverage:
    @pytest.mark.asyncio
    async def test_known_techniques(self, toolkit_with_connectors: ThreatHunterToolkit) -> None:
        techniques = ["T1059.001", "T1110", "T1021"]
        results = await toolkit_with_connectors.check_mitre_coverage(techniques)

        assert len(results) == 3
        for r in results:
            assert r["technique_id"] in techniques
            assert r["technique_name"] != "Unknown"
            assert r["coverage_level"] in ("high", "medium", "low", "none")
            assert isinstance(r["detection_sources"], list)
            assert isinstance(r["gap_identified"], bool)
            assert r["recommendation"]

    @pytest.mark.asyncio
    async def test_unknown_technique(self, toolkit_with_connectors: ThreatHunterToolkit) -> None:
        results = await toolkit_with_connectors.check_mitre_coverage(["T9999"])

        assert len(results) == 1
        assert results[0]["technique_name"] == "Unknown"
        assert results[0]["coverage_level"] == "unknown"
        assert results[0]["gap_identified"] is True

    @pytest.mark.asyncio
    async def test_empty_techniques(self, toolkit_no_connectors: ThreatHunterToolkit) -> None:
        results = await toolkit_no_connectors.check_mitre_coverage([])
        assert results == []

    @pytest.mark.asyncio
    async def test_no_connectors_coverage_none(
        self, toolkit_no_connectors: ThreatHunterToolkit
    ) -> None:
        results = await toolkit_no_connectors.check_mitre_coverage(["T1059.001"])
        assert results[0]["coverage_level"] == "none"


# ---------------------------------------------------------------------------
# correlate_findings
# ---------------------------------------------------------------------------


class TestCorrelateFindings:
    @pytest.mark.asyncio
    async def test_correlates_by_ip(self, toolkit_with_connectors: ThreatHunterToolkit) -> None:
        findings = [
            {
                "type": "ioc",
                "source": "crowdstrike",
                "indicator": "10.0.0.99",
                "severity": "high",
            },
            {
                "type": "behavioral",
                "source": "splunk",
                "match": {"src_ip": "10.0.0.99"},
                "severity": "medium",
            },
        ]
        correlated = await toolkit_with_connectors.correlate_findings(findings)

        assert len(correlated) > 0
        ip_groups = [g for g in correlated if g["entity_type"] == "ip_address"]
        assert len(ip_groups) > 0
        assert ip_groups[0]["entity_value"] == "10.0.0.99"
        assert ip_groups[0]["cross_source"] is True
        assert ip_groups[0]["finding_count"] >= 2

    @pytest.mark.asyncio
    async def test_correlates_by_user(self, toolkit_with_connectors: ThreatHunterToolkit) -> None:
        findings = [
            {
                "type": "behavioral",
                "source": "splunk",
                "user": "admin",
                "severity": "medium",
            },
            {
                "type": "ioc",
                "source": "crowdstrike",
                "user": "admin",
                "severity": "high",
            },
        ]
        correlated = await toolkit_with_connectors.correlate_findings(findings)

        user_groups = [g for g in correlated if g["entity_type"] == "user"]
        assert len(user_groups) > 0
        assert user_groups[0]["entity_value"] == "admin"

    @pytest.mark.asyncio
    async def test_empty_findings(self, toolkit_with_connectors: ThreatHunterToolkit) -> None:
        correlated = await toolkit_with_connectors.correlate_findings([])
        assert correlated == []

    @pytest.mark.asyncio
    async def test_ungrouped_fallback(self, toolkit_with_connectors: ThreatHunterToolkit) -> None:
        """Single finding with no shared attributes produces ungrouped entry."""
        findings = [
            {"type": "ioc", "source": "crowdstrike", "severity": "low"},
        ]
        correlated = await toolkit_with_connectors.correlate_findings(findings)
        assert len(correlated) == 1
        assert correlated[0]["entity_type"] == "ungrouped"

    @pytest.mark.asyncio
    async def test_confidence_increases_with_sources(
        self, toolkit_with_connectors: ThreatHunterToolkit
    ) -> None:
        findings = [
            {
                "type": "ioc",
                "source": "crowdstrike",
                "indicator": "10.0.0.1",
                "severity": "high",
            },
            {
                "type": "behavioral",
                "source": "splunk",
                "match": {"src_ip": "10.0.0.1"},
                "severity": "medium",
            },
            {
                "type": "mitre",
                "source": "mitre",
                "match": {"src_ip": "10.0.0.1"},
                "severity": "high",
            },
        ]
        correlated = await toolkit_with_connectors.correlate_findings(findings)

        ip_groups = [g for g in correlated if g["entity_type"] == "ip_address"]
        assert ip_groups[0]["confidence"] > 0.5


# ---------------------------------------------------------------------------
# track_effectiveness
# ---------------------------------------------------------------------------


class TestTrackEffectiveness:
    @pytest.mark.asyncio
    async def test_records_metrics(self, toolkit_with_connectors: ThreatHunterToolkit) -> None:
        outcome = {
            "threat_found": True,
            "total_findings": 5,
            "correlated_count": 2,
            "recommendations": 3,
            "effectiveness_score": 0.75,
            "duration_ms": 15000,
        }
        result = await toolkit_with_connectors.track_effectiveness("hunt-001", outcome)

        assert result["hunt_id"] == "hunt-001"
        assert result["tracked"] is True
        assert result["threat_found"] is True
        assert result["total_findings"] == 5
        assert result["effectiveness_score"] == 0.75
        assert result["duration_human"] == "15.0s"
        assert result["hunt_quality"] == "excellent"
        assert result["ioc_yield"] == 0.4
        assert "timestamp" in result

    @pytest.mark.asyncio
    async def test_hunt_quality_classification(
        self, toolkit_no_connectors: ThreatHunterToolkit
    ) -> None:
        # Excellent
        r = await toolkit_no_connectors.track_effectiveness(
            "h1", {"threat_found": True, "effectiveness_score": 0.8, "total_findings": 3}
        )
        assert r["hunt_quality"] == "excellent"

        # Good
        r = await toolkit_no_connectors.track_effectiveness(
            "h2", {"threat_found": True, "effectiveness_score": 0.4, "total_findings": 2}
        )
        assert r["hunt_quality"] == "good"

        # Productive
        r = await toolkit_no_connectors.track_effectiveness(
            "h3", {"threat_found": False, "effectiveness_score": 0.5, "total_findings": 3}
        )
        assert r["hunt_quality"] == "productive"

        # Baseline
        r = await toolkit_no_connectors.track_effectiveness(
            "h4", {"threat_found": False, "effectiveness_score": 0.1, "total_findings": 0}
        )
        assert r["hunt_quality"] == "baseline"

    @pytest.mark.asyncio
    async def test_stores_in_hunt_history(self, toolkit_no_connectors: ThreatHunterToolkit) -> None:
        await toolkit_no_connectors.track_effectiveness(
            "h1", {"threat_found": False, "total_findings": 0}
        )
        assert len(toolkit_no_connectors._hunt_history) == 1

    @pytest.mark.asyncio
    async def test_persists_to_repository(self) -> None:
        repo = AsyncMock()
        repo.save_hunt_metrics = AsyncMock()
        toolkit = ThreatHunterToolkit(repository=repo)
        await toolkit.track_effectiveness(
            "hunt-repo", {"threat_found": True, "effectiveness_score": 0.6}
        )
        repo.save_hunt_metrics.assert_called_once()

    @pytest.mark.asyncio
    async def test_duration_formatting(self, toolkit_no_connectors: ThreatHunterToolkit) -> None:
        r = await toolkit_no_connectors.track_effectiveness("h1", {"duration_ms": 500})
        assert r["duration_human"] == "500ms"

        r = await toolkit_no_connectors.track_effectiveness("h2", {"duration_ms": 90000})
        assert r["duration_human"] == "1.5m"


# ---------------------------------------------------------------------------
# Helper method unit tests
# ---------------------------------------------------------------------------


class TestHelperMethods:
    def test_classify_ioc_type_ipv4(self) -> None:
        tk = ThreatHunterToolkit()
        assert tk._classify_ioc_type("192.168.1.1") == "ipv4"

    def test_classify_ioc_type_sha256(self) -> None:
        tk = ThreatHunterToolkit()
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert tk._classify_ioc_type(sha) == "sha256"

    def test_classify_ioc_type_md5(self) -> None:
        tk = ThreatHunterToolkit()
        assert tk._classify_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"

    def test_classify_ioc_type_domain(self) -> None:
        tk = ThreatHunterToolkit()
        assert tk._classify_ioc_type("evil.example.com") == "domain"

    def test_classify_ioc_type_unknown(self) -> None:
        tk = ThreatHunterToolkit()
        assert tk._classify_ioc_type("random-string") == "unknown"

    def test_map_hypothesis_to_mitre(self) -> None:
        tk = ThreatHunterToolkit()
        techniques = tk._map_hypothesis_to_mitre("lateral movement via RDP")
        assert "T1021" in techniques
        assert "T1021.001" in techniques

    def test_identify_data_sources(self) -> None:
        tk = ThreatHunterToolkit()
        sources = tk._identify_data_sources("phishing email with malicious attachment")
        assert "email_logs" in sources

    def test_score_hypothesis_confidence(self) -> None:
        tk = ThreatHunterToolkit()
        # Empty hypothesis
        assert tk._score_hypothesis_confidence("", []) == 0.1
        # Simple hypothesis
        score = tk._score_hypothesis_confidence("brute force attack", ["T1110"])
        assert score > 0.3
        # Detailed hypothesis
        detailed = (
            "Adversary is performing brute force credential attacks "
            "against RDP services on ip address 10.0.0.1 using known compromised credentials"
        )
        detailed_score = tk._score_hypothesis_confidence(detailed, ["T1110", "T1021.001"])
        assert detailed_score > score

    def test_max_severity(self) -> None:
        tk = ThreatHunterToolkit()
        assert tk._max_severity(["low", "high", "medium"]) == "high"
        assert tk._max_severity(["low"]) == "low"
        assert tk._max_severity([]) == "low"
        assert tk._max_severity(["critical", "high"]) == "critical"

    def test_is_ip_like(self) -> None:
        tk = ThreatHunterToolkit()
        assert tk._is_ip_like("192.168.1.1") is True
        assert tk._is_ip_like("evil.com") is False
        assert tk._is_ip_like("not-an-ip") is False

    def test_format_duration(self) -> None:
        tk = ThreatHunterToolkit()
        assert tk._format_duration(500) == "500ms"
        assert tk._format_duration(5000) == "5.0s"
        assert tk._format_duration(90000) == "1.5m"
        assert tk._format_duration(7200000) == "2.0h"
