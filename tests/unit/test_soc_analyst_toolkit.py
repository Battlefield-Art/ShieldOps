"""Tests for SOC Analyst Toolkit production methods.

Covers:
- triage_alert: severity scoring, source reliability, asset criticality, FP rate adjustment
- enrich_alert: CrowdStrike + Splunk connector integration, heuristic fallback
- classify_true_false_positive: LLM classification + heuristic fallback
- correlate_alerts: grouping by shared IP, user, timeframe, MITRE technique
- escalate: routing to investigation/incident_response/soc_queue/dismiss
- track_metrics: TP/FP rates, mean triage time, escalation rate
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.agents.soc_analyst.tools import SOCAnalystToolkit

# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def toolkit() -> SOCAnalystToolkit:
    return SOCAnalystToolkit()


@pytest.fixture
def toolkit_with_connectors() -> SOCAnalystToolkit:
    crowdstrike = AsyncMock()
    crowdstrike.get_threat_graph = AsyncMock(return_value={"resources": [{"id": "det-1"}]})
    crowdstrike.get_detections = AsyncMock(
        return_value=[
            {
                "detection_id": "det-100",
                "max_severity_displayname": "High",
                "tactic": "Execution",
                "technique": "T1059",
            }
        ]
    )

    splunk = AsyncMock()
    splunk.search_spl = AsyncMock(
        return_value=[
            {
                "sourcetype": "syslog",
                "count": "5",
                "index": "main",
                "src_ip": "10.0.0.1",
                "dest_ip": "192.168.1.1",
            }
        ]
    )

    return SOCAnalystToolkit(connector_router={"crowdstrike": crowdstrike, "splunk": splunk})


@pytest.fixture
def sample_alert() -> dict:
    return {
        "alert_id": "ALERT-001",
        "alert_type": "brute_force",
        "severity": "high",
        "source": "crowdstrike",
        "source_ip": "10.0.0.1",
        "dest_ip": "192.168.1.100",
        "user": "admin",
        "hostname": "web-server-01",
        "asset_criticality": "critical",
    }


@pytest.fixture
def enriched_alert_tp() -> dict:
    """Enriched alert that should classify as true positive."""
    return {
        "indicators": ["10.0.0.1", "192.168.1.100"],
        "ioc_matches": ["10.0.0.1", "evil.com"],
        "crowdstrike_detections": [{"detection_id": "d1"}, {"detection_id": "d2"}],
        "splunk_correlated_events": [{"source": "syslog"}, {"source": "fw"}, {"source": "ids"}],
        "mitre_techniques": ["T1110", "T1078"],
        "reputation_score": 0.85,
        "threat_feeds": ["abuse_ch", "virustotal"],
        "related_campaigns": [],
    }


@pytest.fixture
def enriched_alert_fp() -> dict:
    """Enriched alert that should classify as false positive."""
    return {
        "indicators": ["10.0.0.1"],
        "ioc_matches": [],
        "crowdstrike_detections": [],
        "splunk_correlated_events": [],
        "mitre_techniques": [],
        "reputation_score": 0.1,
        "threat_feeds": [],
        "related_campaigns": [],
    }


# ── triage_alert ────────────────────────────────────────────────────────────


class TestTriageAlert:
    @pytest.mark.asyncio
    async def test_critical_severity_high_score(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.triage_alert(
            {
                "severity": "critical",
                "source": "crowdstrike",
                "asset_criticality": "critical",
                "alert_type": "malware_detected",
            }
        )
        assert result["triage_score"] > 75
        assert result["decision"] == "investigate"
        assert result["tier"] == 3

    @pytest.mark.asyncio
    async def test_low_severity_low_score(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.triage_alert(
            {
                "severity": "low",
                "source": "unknown",
                "asset_criticality": "low",
                "alert_type": "port_scan",
            }
        )
        assert result["triage_score"] < 40
        assert result["decision"] in ("dismiss", "monitor")
        assert result["tier"] <= 2

    @pytest.mark.asyncio
    async def test_known_false_positive_dismissed(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.triage_alert(
            {
                "severity": "high",
                "known_false_positive": True,
            }
        )
        assert result["decision"] == "dismiss"
        assert result["triage_score"] <= 10.0
        assert result["tier"] == 1

    @pytest.mark.asyncio
    async def test_source_reliability_applied(self, toolkit: SOCAnalystToolkit):
        cs_result = await toolkit.triage_alert(
            {
                "severity": "high",
                "source": "crowdstrike",
                "asset_criticality": "medium",
            }
        )
        unk_result = await toolkit.triage_alert(
            {
                "severity": "high",
                "source": "unknown",
                "asset_criticality": "medium",
            }
        )
        assert cs_result["triage_score"] > unk_result["triage_score"]

    @pytest.mark.asyncio
    async def test_asset_criticality_multiplier(self, toolkit: SOCAnalystToolkit):
        crit_result = await toolkit.triage_alert(
            {
                "severity": "medium",
                "source": "splunk",
                "asset_criticality": "critical",
            }
        )
        low_result = await toolkit.triage_alert(
            {
                "severity": "medium",
                "source": "splunk",
                "asset_criticality": "low",
            }
        )
        assert crit_result["triage_score"] > low_result["triage_score"]

    @pytest.mark.asyncio
    async def test_triage_returns_all_fields(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.triage_alert({"severity": "medium"})
        assert "triage_score" in result
        assert "tier" in result
        assert "decision" in result
        assert "source_reliability" in result
        assert "fp_base_rate" in result
        assert "triage_time_ms" in result

    @pytest.mark.asyncio
    async def test_triage_increments_metrics(self, toolkit: SOCAnalystToolkit):
        await toolkit.triage_alert({"severity": "high"})
        await toolkit.triage_alert({"severity": "low"})
        metrics = await toolkit.track_metrics()
        assert metrics["alerts_triaged"] == 2


# ── enrich_alert ────────────────────────────────────────────────────────────


class TestEnrichAlert:
    @pytest.mark.asyncio
    async def test_enrichment_extracts_indicators(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.enrich_alert(
            {
                "source_ip": "10.0.0.1",
                "dest_ip": "192.168.1.1",
                "domain": "evil.com",
            }
        )
        assert "10.0.0.1" in result["indicators"]
        assert "evil.com" in result["indicators"]

    @pytest.mark.asyncio
    async def test_enrichment_maps_mitre(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.enrich_alert(
            {
                "alert_type": "brute_force",
                "source_ip": "10.0.0.1",
            }
        )
        assert "T1110" in result["mitre_techniques"]

    @pytest.mark.asyncio
    async def test_enrichment_heuristic_reputation(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.enrich_alert(
            {
                "severity": "critical",
                "alert_type": "unknown",
            }
        )
        assert result["reputation_score"] > 0.0

    @pytest.mark.asyncio
    async def test_enrichment_with_crowdstrike(
        self, toolkit_with_connectors: SOCAnalystToolkit, sample_alert: dict
    ):
        result = await toolkit_with_connectors.enrich_alert(sample_alert)
        assert len(result["crowdstrike_detections"]) > 0
        cs = toolkit_with_connectors._connector_router["crowdstrike"]
        cs.get_threat_graph.assert_called()

    @pytest.mark.asyncio
    async def test_enrichment_with_splunk(
        self, toolkit_with_connectors: SOCAnalystToolkit, sample_alert: dict
    ):
        result = await toolkit_with_connectors.enrich_alert(sample_alert)
        assert len(result["splunk_correlated_events"]) > 0
        sp = toolkit_with_connectors._connector_router["splunk"]
        sp.search_spl.assert_called()

    @pytest.mark.asyncio
    async def test_enrichment_graceful_connector_failure(self):
        cs = AsyncMock()
        cs.get_threat_graph = AsyncMock(side_effect=ConnectionError("timeout"))
        cs.get_detections = AsyncMock(side_effect=ConnectionError("timeout"))
        sp = AsyncMock()
        sp.search_spl = AsyncMock(side_effect=ConnectionError("timeout"))
        tk = SOCAnalystToolkit(connector_router={"crowdstrike": cs, "splunk": sp})
        result = await tk.enrich_alert({"source_ip": "10.0.0.1", "severity": "high"})
        # Should still return valid enrichment with heuristic data
        assert "reputation_score" in result
        assert result["reputation_score"] > 0.0


# ── classify_true_false_positive ────────────────────────────────────────────


class TestClassifyTrueFalsePositive:
    @pytest.mark.asyncio
    async def test_heuristic_true_positive(
        self, toolkit: SOCAnalystToolkit, enriched_alert_tp: dict
    ):
        result = await toolkit.classify_true_false_positive(enriched_alert_tp)
        assert result["classification"] == "true_positive"
        assert result["confidence"] > 0.5
        assert result["method"] == "heuristic"
        assert len(result["key_signals"]) > 0

    @pytest.mark.asyncio
    async def test_heuristic_false_positive(
        self, toolkit: SOCAnalystToolkit, enriched_alert_fp: dict
    ):
        result = await toolkit.classify_true_false_positive(enriched_alert_fp)
        assert result["classification"] == "false_positive"
        assert result["confidence"] > 0.5
        assert result["method"] == "heuristic"

    @pytest.mark.asyncio
    async def test_heuristic_needs_investigation(self, toolkit: SOCAnalystToolkit):
        # Moderate signals → needs_investigation
        result = await toolkit.classify_true_false_positive(
            {
                "ioc_matches": ["10.0.0.1"],
                "crowdstrike_detections": [{"id": "d1"}],
                "splunk_correlated_events": [{"s": 1}, {"s": 2}, {"s": 3}],
                "mitre_techniques": ["T1110"],
                "reputation_score": 0.4,
                "threat_feeds": [],
            }
        )
        assert result["classification"] == "needs_investigation"

    @pytest.mark.asyncio
    async def test_llm_classification_used_when_available(
        self, toolkit: SOCAnalystToolkit, enriched_alert_tp: dict
    ):
        mock_result = MagicMock()
        mock_result.classification = "true_positive"
        mock_result.confidence = 0.92
        mock_result.reasoning = "Strong IOC signals"
        mock_result.key_signals = ["2 IOC matches", "High reputation"]

        with patch(
            "shieldops.agents.soc_analyst.tools.llm_structured",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            result = await toolkit.classify_true_false_positive(enriched_alert_tp)
            assert result["method"] == "llm"
            assert result["classification"] == "true_positive"
            assert result["confidence"] == 0.92

    @pytest.mark.asyncio
    async def test_llm_failure_falls_back_to_heuristic(
        self, toolkit: SOCAnalystToolkit, enriched_alert_tp: dict
    ):
        with patch(
            "shieldops.agents.soc_analyst.tools.llm_structured",
            new_callable=AsyncMock,
            side_effect=RuntimeError("LLM unavailable"),
        ):
            result = await toolkit.classify_true_false_positive(enriched_alert_tp)
            assert result["method"] == "heuristic"
            assert result["classification"] in (
                "true_positive",
                "false_positive",
                "needs_investigation",
            )

    @pytest.mark.asyncio
    async def test_classification_updates_metrics(
        self, toolkit: SOCAnalystToolkit, enriched_alert_tp: dict
    ):
        await toolkit.classify_true_false_positive(enriched_alert_tp)
        metrics = await toolkit.track_metrics()
        classified = (
            metrics["true_positives"] + metrics["false_positives"] + metrics["needs_investigation"]
        )
        assert classified >= 1


# ── correlate_alerts ────────────────────────────────────────────────────────


class TestCorrelateAlerts:
    @pytest.mark.asyncio
    async def test_empty_list(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.correlate_alerts([])
        assert result == []

    @pytest.mark.asyncio
    async def test_single_alert_no_groups(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.correlate_alerts([{"alert_id": "A1", "source_ip": "10.0.0.1"}])
        assert result == []

    @pytest.mark.asyncio
    async def test_shared_ip_grouping(self, toolkit: SOCAnalystToolkit):
        alerts = [
            {"alert_id": "A1", "source_ip": "10.0.0.1"},
            {"alert_id": "A2", "source_ip": "10.0.0.1"},
            {"alert_id": "A3", "source_ip": "10.0.0.2"},
        ]
        groups = await toolkit.correlate_alerts(alerts)
        ip_groups = [g for g in groups if g["correlation_type"] == "shared_ip"]
        assert len(ip_groups) == 1
        assert ip_groups[0]["key"] == "10.0.0.1"
        assert ip_groups[0]["alert_count"] == 2

    @pytest.mark.asyncio
    async def test_shared_user_grouping(self, toolkit: SOCAnalystToolkit):
        alerts = [
            {"alert_id": "A1", "user": "admin"},
            {"alert_id": "A2", "user": "admin"},
            {"alert_id": "A3", "user": "guest"},
        ]
        groups = await toolkit.correlate_alerts(alerts)
        user_groups = [g for g in groups if g["correlation_type"] == "shared_user"]
        assert len(user_groups) == 1
        assert user_groups[0]["key"] == "admin"

    @pytest.mark.asyncio
    async def test_shared_mitre_grouping(self, toolkit: SOCAnalystToolkit):
        alerts = [
            {"alert_id": "A1", "mitre_techniques": ["T1110"]},
            {"alert_id": "A2", "mitre_techniques": ["T1110", "T1078"]},
        ]
        groups = await toolkit.correlate_alerts(alerts)
        mitre_groups = [g for g in groups if g["correlation_type"] == "shared_mitre_technique"]
        assert len(mitre_groups) >= 1

    @pytest.mark.asyncio
    async def test_timeframe_grouping(self, toolkit: SOCAnalystToolkit):
        now = datetime.now(UTC)
        alerts = [
            {"alert_id": "A1", "timestamp": now.isoformat()},
            {"alert_id": "A2", "timestamp": (now + timedelta(seconds=60)).isoformat()},
            {"alert_id": "A3", "timestamp": (now + timedelta(hours=2)).isoformat()},
        ]
        groups = await toolkit.correlate_alerts(alerts)
        time_groups = [g for g in groups if g["correlation_type"] == "shared_timeframe"]
        assert len(time_groups) == 1
        assert time_groups[0]["alert_count"] == 2

    @pytest.mark.asyncio
    async def test_groups_contain_alert_data(self, toolkit: SOCAnalystToolkit):
        alerts = [
            {"alert_id": "A1", "source_ip": "10.0.0.1", "severity": "high"},
            {"alert_id": "A2", "source_ip": "10.0.0.1", "severity": "medium"},
        ]
        groups = await toolkit.correlate_alerts(alerts)
        assert len(groups) >= 1
        assert "alerts" in groups[0]
        assert len(groups[0]["alerts"]) == 2


# ── escalate ────────────────────────────────────────────────────────────────


class TestEscalate:
    @pytest.mark.asyncio
    async def test_critical_routes_to_incident_response(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.escalate(
            {"alert_id": "A1", "severity": "critical"},
            {"classification": "true_positive", "confidence": 0.9},
        )
        assert result["target"] == "incident_response"
        assert result["priority"] == "p1"

    @pytest.mark.asyncio
    async def test_tp_high_confidence_routes_to_investigation(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.escalate(
            {"alert_id": "A1", "severity": "high"},
            {"classification": "true_positive", "confidence": 0.85},
        )
        assert result["target"] == "investigation"
        assert result["priority"] == "p2"

    @pytest.mark.asyncio
    async def test_tp_low_confidence_routes_to_queue(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.escalate(
            {"alert_id": "A1", "severity": "high"},
            {"classification": "true_positive", "confidence": 0.5},
        )
        assert result["target"] == "soc_queue"
        assert result["priority"] == "p3"

    @pytest.mark.asyncio
    async def test_fp_dismissed(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.escalate(
            {"alert_id": "A1", "severity": "low"},
            {"classification": "false_positive", "confidence": 0.8},
        )
        assert result["target"] == "dismiss"
        assert result["priority"] == "p5"

    @pytest.mark.asyncio
    async def test_needs_investigation_to_queue(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.escalate(
            {"alert_id": "A1", "severity": "medium"},
            {"classification": "needs_investigation", "confidence": 0.6},
        )
        assert result["target"] == "soc_queue"

    @pytest.mark.asyncio
    async def test_escalation_has_required_fields(self, toolkit: SOCAnalystToolkit):
        result = await toolkit.escalate(
            {"alert_id": "A1", "severity": "high"},
            {"classification": "true_positive", "confidence": 0.9},
        )
        assert "alert_id" in result
        assert "target" in result
        assert "priority" in result
        assert "reason" in result
        assert "timestamp" in result

    @pytest.mark.asyncio
    async def test_escalation_increments_metrics(self, toolkit: SOCAnalystToolkit):
        await toolkit.escalate(
            {"alert_id": "A1", "severity": "high"},
            {"classification": "true_positive", "confidence": 0.9},
        )
        metrics = await toolkit.track_metrics()
        assert metrics["escalations"] == 1


# ── track_metrics ───────────────────────────────────────────────────────────


class TestTrackMetrics:
    @pytest.mark.asyncio
    async def test_initial_metrics_empty(self, toolkit: SOCAnalystToolkit):
        metrics = await toolkit.track_metrics()
        assert metrics["alerts_triaged"] == 0
        assert metrics["true_positive_rate"] == 0.0
        assert metrics["false_positive_rate"] == 0.0
        assert metrics["mean_triage_time_ms"] == 0.0
        assert metrics["escalation_rate"] == 0.0

    @pytest.mark.asyncio
    async def test_metrics_after_triage_and_classify(self, toolkit: SOCAnalystToolkit):
        await toolkit.triage_alert({"severity": "high", "alert_type": "malware_detected"})
        await toolkit.classify_true_false_positive(
            {
                "ioc_matches": ["evil.com"],
                "crowdstrike_detections": [{"id": "d1"}],
                "splunk_correlated_events": [{"s": 1}, {"s": 2}, {"s": 3}],
                "mitre_techniques": ["T1059", "T1204"],
                "reputation_score": 0.85,
                "threat_feeds": ["vt"],
            }
        )
        metrics = await toolkit.track_metrics()
        assert metrics["alerts_triaged"] == 1
        assert metrics["true_positives"] >= 1

    @pytest.mark.asyncio
    async def test_metrics_with_additional_decisions(self, toolkit: SOCAnalystToolkit):
        decisions = [
            {"classification": "true_positive", "alert_id": "A1"},
            {"classification": "false_positive", "alert_id": "A2"},
            {"classification": "true_positive", "alert_id": "A3"},
        ]
        metrics = await toolkit.track_metrics(decisions=decisions)
        assert metrics["alerts_triaged"] == 3
        assert metrics["true_positives"] == 2
        assert metrics["false_positives"] == 1
        assert metrics["true_positive_rate"] > 0.0

    @pytest.mark.asyncio
    async def test_recent_decisions_capped(self, toolkit: SOCAnalystToolkit):
        decisions = [{"classification": "true_positive", "alert_id": f"A{i}"} for i in range(30)]
        metrics = await toolkit.track_metrics(decisions=decisions)
        assert len(metrics["recent_decisions"]) <= 20


# ── Integration: Full Pipeline ──────────────────────────────────────────────


class TestFullPipeline:
    @pytest.mark.asyncio
    async def test_triage_enrich_classify_escalate(self, sample_alert: dict):
        tk = SOCAnalystToolkit()

        # 1. Triage
        triage = await tk.triage_alert(sample_alert)
        assert triage["decision"] in ("investigate", "monitor", "dismiss")

        # 2. Enrich
        enrichment = await tk.enrich_alert(sample_alert)
        assert "mitre_techniques" in enrichment

        # 3. Classify
        classification = await tk.classify_true_false_positive(enrichment)
        assert classification["classification"] in (
            "true_positive",
            "false_positive",
            "needs_investigation",
        )

        # 4. Escalate
        escalation = await tk.escalate(sample_alert, classification)
        assert escalation["target"] in (
            "investigation",
            "incident_response",
            "soc_queue",
            "dismiss",
        )

        # 5. Metrics
        metrics = await tk.track_metrics()
        assert metrics["alerts_triaged"] >= 1
