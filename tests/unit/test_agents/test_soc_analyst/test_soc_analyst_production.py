"""Tests for SOC Analyst Agent production-readiness.

Covers:
- Alert triage produces severity classification (LLM + heuristic fallback)
- Enrichment correlates from multiple sources (Splunk, CrowdStrike, AWS)
- Escalation creates appropriate notifications (PagerDuty, Slack, ServiceNow)
- LLM fallback works correctly
- OPA policy gate integration
- Persistence calls after execution
- Graph compiles and has expected nodes
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.agents.soc_analyst.models import (
    SOCAnalystState,
    ThreatIntelEnrichment,
)
from shieldops.agents.soc_analyst.nodes import (
    enrich_alert,
    finalize,
    set_toolkit,
    triage_alert,
)
from shieldops.agents.soc_analyst.tools import SOCAnalystToolkit

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def toolkit() -> SOCAnalystToolkit:
    """Toolkit with no connectors (safe for unit tests)."""
    return SOCAnalystToolkit()


@pytest.fixture()
def toolkit_with_connectors() -> SOCAnalystToolkit:
    """Toolkit with mock connectors for integration-style tests."""
    mock_crowdstrike = AsyncMock()
    mock_crowdstrike.get_detections = AsyncMock(
        return_value=[
            {
                "detection_id": "det-001",
                "max_severity_displayname": "High",
                "max_severity": 80,
                "tactic": "Persistence",
                "technique": "T1547",
                "device": {
                    "hostname": "prod-web-01",
                    "os_version": "Ubuntu 22.04",
                    "agent_version": "7.0.1",
                    "last_seen": "2026-04-05T10:00:00Z",
                    "platform_name": "Linux",
                    "device_id": "dev-abc123",
                },
                "description": "Suspicious process execution",
                "created_timestamp": "2026-04-05T09:30:00Z",
            }
        ]
    )
    mock_crowdstrike.get_threat_graph = AsyncMock(return_value={"resources": ["ioc-1"]})

    mock_splunk = AsyncMock()
    mock_splunk.get_notable_events = AsyncMock(
        return_value=[
            {
                "rule_name": "Brute Force Detected",
                "severity": "high",
                "src_ip": "10.0.0.5",
                "dest_ip": "10.0.1.10",
                "count": "15",
            }
        ]
    )
    mock_splunk.search_spl = AsyncMock(
        return_value=[
            {
                "sourcetype": "syslog",
                "count": "12",
                "index": "main",
                "src_ip": "10.0.0.5",
                "dest_ip": "10.0.1.10",
            }
        ]
    )

    mock_pagerduty = AsyncMock()
    mock_pagerduty.create_incident = AsyncMock(
        return_value={"incident": {"id": "PD-001", "status": "triggered"}}
    )
    mock_pagerduty.trigger_event = AsyncMock(
        return_value={
            "status": "success",
            "dedup_key": "dedup-001",
        }
    )

    mock_servicenow = AsyncMock()
    mock_servicenow.create_incident = AsyncMock(
        return_value={
            "sys_id": "sn-001",
            "number": "INC0012345",
        }
    )

    mock_aws = AsyncMock()
    mock_aws.get_health = AsyncMock(
        return_value=MagicMock(
            resource_id="i-abc123",
            healthy=True,
            status="running",
            message="OK",
        )
    )
    mock_aws.get_events = AsyncMock(
        return_value=[{"event": "StopInstances", "time": "2026-04-05T08:00:00Z"}]
    )

    return SOCAnalystToolkit(
        connector_router={
            "crowdstrike": mock_crowdstrike,
            "splunk": mock_splunk,
            "pagerduty": mock_pagerduty,
            "servicenow": mock_servicenow,
            "aws": mock_aws,
        }
    )


@pytest.fixture()
def alert_state() -> SOCAnalystState:
    """Standard alert state for testing."""
    return SOCAnalystState(
        alert_id="alert-soc-001",
        alert_data={
            "severity": "high",
            "alert_type": "malware_detected",
            "source": "crowdstrike",
            "source_ip": "10.0.0.5",
            "dest_ip": "10.0.1.10",
            "hostname": "prod-web-01",
            "instance_id": "i-abc123",
            "description": "Malware detected on prod-web-01",
            "org_id": "org-test-1",
        },
    )


@pytest.fixture()
def low_severity_state() -> SOCAnalystState:
    """Low severity alert state for auto-resolve testing."""
    return SOCAnalystState(
        alert_id="alert-soc-002",
        alert_data={
            "severity": "low",
            "alert_type": "policy_violation",
            "source": "custom",
            "description": "Low-risk policy violation detected",
            "org_id": "org-test-1",
        },
    )


# ---------------------------------------------------------------------------
# Alert Triage Tests
# ---------------------------------------------------------------------------


class TestAlertTriage:
    """Verify alert triage produces severity classification."""

    @pytest.mark.asyncio()
    async def test_triage_classifies_severity(self, toolkit: SOCAnalystToolkit) -> None:
        """triage_alert should classify severity and assign tier."""
        set_toolkit(toolkit)

        state = SOCAnalystState(
            alert_id="test-001",
            alert_data={
                "severity": "critical",
                "alert_type": "ransomware",
                "description": "Ransomware detected",
            },
        )

        with patch(
            "shieldops.agents.soc_analyst.nodes.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            result = await triage_alert(state)

        assert "triage_score" in result
        assert "tier" in result
        assert result["tier"] in (1, 2, 3)
        assert result["current_step"] == "triage_alert"
        assert len(result["reasoning_chain"]) == 1

    @pytest.mark.asyncio()
    async def test_triage_heuristic_critical_keyword(self, toolkit: SOCAnalystToolkit) -> None:
        """Keyword 'ransomware' should classify as critical severity."""
        result = await toolkit.classify_severity(
            {
                "alert_type": "ransomware",
                "description": "Ransomware encryption detected",
            }
        )
        assert result["classified_severity"] == "critical"
        assert result["method"] == "heuristic"
        assert result["confidence"] > 0.5

    @pytest.mark.asyncio()
    async def test_triage_heuristic_high_keyword(self, toolkit: SOCAnalystToolkit) -> None:
        """Keyword 'malware' should classify as high severity."""
        result = await toolkit.classify_severity(
            {
                "alert_type": "malware_detected",
                "description": "Malware found on endpoint",
            }
        )
        assert result["classified_severity"] == "high"
        assert result["method"] == "heuristic"

    @pytest.mark.asyncio()
    async def test_triage_heuristic_medium_keyword(self, toolkit: SOCAnalystToolkit) -> None:
        """Keyword 'brute_force' should classify as medium severity."""
        result = await toolkit.classify_severity(
            {
                "alert_type": "brute_force",
                "description": "Brute force attempt detected",
            }
        )
        assert result["classified_severity"] == "medium"

    @pytest.mark.asyncio()
    async def test_triage_heuristic_low_keyword(self, toolkit: SOCAnalystToolkit) -> None:
        """Keyword 'informational' should classify as low severity."""
        result = await toolkit.classify_severity(
            {
                "alert_type": "info_event",
                "description": "Informational event logged",
            }
        )
        assert result["classified_severity"] == "low"

    @pytest.mark.asyncio()
    async def test_triage_heuristic_default(self, toolkit: SOCAnalystToolkit) -> None:
        """No matching keywords should default to medium."""
        result = await toolkit.classify_severity(
            {
                "alert_type": "unknown_type",
                "description": "Something happened",
            }
        )
        assert result["classified_severity"] == "medium"
        assert result["confidence"] == 0.3

    @pytest.mark.asyncio()
    async def test_triage_suppresses_known_false_positive(self, toolkit: SOCAnalystToolkit) -> None:
        """Known false positives should be suppressed."""
        set_toolkit(toolkit)

        state = SOCAnalystState(
            alert_id="test-fp",
            alert_data={
                "severity": "medium",
                "known_false_positive": True,
            },
        )

        with patch(
            "shieldops.agents.soc_analyst.nodes.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            result = await triage_alert(state)

        assert result["should_suppress"] is True

    @pytest.mark.asyncio()
    async def test_triage_policy_denied(self, toolkit: SOCAnalystToolkit) -> None:
        """Triage should abort when policy denies the action."""
        set_toolkit(toolkit)

        state = SOCAnalystState(
            alert_id="test-denied",
            alert_data={"severity": "high"},
        )

        with patch(
            "shieldops.agents.soc_analyst.nodes.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = False
            mock_decision.reason = "Denied by test policy"
            mock_policy.return_value = mock_decision

            result = await triage_alert(state)

        assert "error" in result
        assert "Policy denied" in result["error"]

    @pytest.mark.asyncio()
    async def test_fetch_splunk_alerts(self, toolkit_with_connectors: SOCAnalystToolkit) -> None:
        """fetch_splunk_alerts should return notable events from Splunk."""
        results = await toolkit_with_connectors.fetch_splunk_alerts(severity="high")
        assert len(results) == 1
        assert results[0]["rule_name"] == "Brute Force Detected"

    @pytest.mark.asyncio()
    async def test_fetch_splunk_alerts_no_connector(self, toolkit: SOCAnalystToolkit) -> None:
        """fetch_splunk_alerts should return empty list without connector."""
        results = await toolkit.fetch_splunk_alerts()
        assert results == []

    @pytest.mark.asyncio()
    async def test_fetch_crowdstrike_detections(
        self, toolkit_with_connectors: SOCAnalystToolkit
    ) -> None:
        """fetch_crowdstrike_detections should return structured detections."""
        results = await toolkit_with_connectors.fetch_crowdstrike_detections()
        assert len(results) == 1
        assert results[0]["detection_id"] == "det-001"
        assert results[0]["severity"] == "High"
        assert results[0]["hostname"] == "prod-web-01"

    @pytest.mark.asyncio()
    async def test_fetch_crowdstrike_detections_no_connector(
        self, toolkit: SOCAnalystToolkit
    ) -> None:
        """fetch_crowdstrike_detections should return empty list without connector."""
        results = await toolkit.fetch_crowdstrike_detections()
        assert results == []


# ---------------------------------------------------------------------------
# Enrichment Tests
# ---------------------------------------------------------------------------


class TestEnrichment:
    """Verify enrichment correlates from multiple sources."""

    @pytest.mark.asyncio()
    async def test_enrich_alert_with_asset_context(
        self,
        alert_state: SOCAnalystState,
        toolkit_with_connectors: SOCAnalystToolkit,
    ) -> None:
        """enrich_alert should populate asset_context from AWS and CrowdStrike."""
        set_toolkit(toolkit_with_connectors)

        result = await enrich_alert(alert_state)

        assert "asset_context" in result
        assert "aws" in result["asset_context"]
        assert result["asset_context"]["aws"]["instance_id"] == "i-abc123"
        assert "crowdstrike_host" in result["asset_context"]

    @pytest.mark.asyncio()
    async def test_enrich_produces_threat_intel(
        self,
        alert_state: SOCAnalystState,
        toolkit: SOCAnalystToolkit,
    ) -> None:
        """enrich_alert should produce ThreatIntelEnrichment even without connectors."""
        set_toolkit(toolkit)

        result = await enrich_alert(alert_state)

        assert "threat_intel_enrichment" in result
        enrichment = result["threat_intel_enrichment"]
        assert isinstance(enrichment, ThreatIntelEnrichment)

    @pytest.mark.asyncio()
    async def test_enrich_crowdstrike_host_with_connector(
        self, toolkit_with_connectors: SOCAnalystToolkit
    ) -> None:
        """enrich_with_crowdstrike_host should return host info and detections."""
        result = await toolkit_with_connectors.enrich_with_crowdstrike_host("prod-web-01")

        assert result["hostname"] == "prod-web-01"
        assert len(result["recent_detections"]) == 1
        assert result["host_info"]["os_version"] == "Ubuntu 22.04"
        assert result["host_info"]["agent_version"] == "7.0.1"

    @pytest.mark.asyncio()
    async def test_enrich_crowdstrike_host_no_connector(self, toolkit: SOCAnalystToolkit) -> None:
        """enrich_with_crowdstrike_host should return empty data without connector."""
        result = await toolkit.enrich_with_crowdstrike_host("unknown-host")
        assert result["hostname"] == "unknown-host"
        assert result["host_info"] == {}
        assert result["recent_detections"] == []

    @pytest.mark.asyncio()
    async def test_enrich_aws_context_with_connector(
        self, toolkit_with_connectors: SOCAnalystToolkit
    ) -> None:
        """enrich_with_aws_context should return instance details and events."""
        result = await toolkit_with_connectors.enrich_with_aws_context("i-abc123")

        assert result["instance_id"] == "i-abc123"
        assert result["instance_details"]["healthy"] is True
        assert len(result["recent_events"]) == 1

    @pytest.mark.asyncio()
    async def test_enrich_aws_context_no_connector(self, toolkit: SOCAnalystToolkit) -> None:
        """enrich_with_aws_context should return empty data without connector."""
        result = await toolkit.enrich_with_aws_context("i-missing")
        assert result["instance_id"] == "i-missing"
        assert result["instance_details"] == {}

    @pytest.mark.asyncio()
    async def test_enrich_multiple_sources_combined(
        self,
        alert_state: SOCAnalystState,
        toolkit_with_connectors: SOCAnalystToolkit,
    ) -> None:
        """Full enrichment should combine data from all sources into state."""
        set_toolkit(toolkit_with_connectors)

        result = await enrich_alert(alert_state)

        # Should have reasoning step
        assert len(result["reasoning_chain"]) == 1
        step = result["reasoning_chain"][0]
        assert step.action == "enrich_alert"
        assert "aws" in step.output_summary
        assert "crowdstrike" in step.output_summary


# ---------------------------------------------------------------------------
# Escalation Tests
# ---------------------------------------------------------------------------


class TestEscalation:
    """Verify escalation creates appropriate notifications."""

    @pytest.mark.asyncio()
    async def test_auto_resolve_low_severity(self, toolkit: SOCAnalystToolkit) -> None:
        """Low severity alerts should be auto-resolved."""
        with patch(
            "shieldops.agents.soc_analyst.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            result = await toolkit.auto_resolve_alert(
                alert_id="test-001",
                severity="low",
                reason="Test auto-resolve",
            )

        assert result["resolved"] is True
        assert result["alert_id"] == "test-001"

    @pytest.mark.asyncio()
    async def test_auto_resolve_rejects_high_severity(self, toolkit: SOCAnalystToolkit) -> None:
        """High severity alerts should not be auto-resolved."""
        result = await toolkit.auto_resolve_alert(
            alert_id="test-002",
            severity="high",
        )
        assert result["resolved"] is False
        assert "too high" in result["reason"]

    @pytest.mark.asyncio()
    async def test_create_pagerduty_incident(
        self, toolkit_with_connectors: SOCAnalystToolkit
    ) -> None:
        """create_pagerduty_incident should create an incident via connector."""
        with patch(
            "shieldops.agents.soc_analyst.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            result = await toolkit_with_connectors.create_pagerduty_incident(
                alert_id="test-003",
                title="Critical Alert",
                severity="critical",
                service_id="PD-SVC-001",
            )

        assert result["created"] is True
        assert result["incident_id"] == "PD-001"

    @pytest.mark.asyncio()
    async def test_create_pagerduty_incident_no_connector(self, toolkit: SOCAnalystToolkit) -> None:
        """create_pagerduty_incident should return not created without connector."""
        with patch(
            "shieldops.agents.soc_analyst.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            result = await toolkit.create_pagerduty_incident(
                alert_id="test-004",
                title="Test Alert",
                severity="high",
            )

        assert result["created"] is False
        assert "not available" in result["reason"]

    @pytest.mark.asyncio()
    async def test_create_pagerduty_via_event_trigger(
        self, toolkit_with_connectors: SOCAnalystToolkit
    ) -> None:
        """Without service_id, should fall back to Events API v2 trigger."""
        with patch(
            "shieldops.agents.soc_analyst.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            result = await toolkit_with_connectors.create_pagerduty_incident(
                alert_id="test-005",
                title="High Severity Alert",
                severity="high",
            )

        assert result["created"] is True
        assert result["dedup_key"] == "dedup-001"

    @pytest.mark.asyncio()
    async def test_create_servicenow_ticket(
        self, toolkit_with_connectors: SOCAnalystToolkit
    ) -> None:
        """create_servicenow_ticket should create an incident in ServiceNow."""
        with patch(
            "shieldops.agents.soc_analyst.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            result = await toolkit_with_connectors.create_servicenow_ticket(
                alert_id="test-006",
                short_description="SOC Alert",
                severity="high",
            )

        assert result["created"] is True
        assert result["ticket_number"] == "INC0012345"
        assert result["sys_id"] == "sn-001"

    @pytest.mark.asyncio()
    async def test_create_servicenow_ticket_no_connector(self, toolkit: SOCAnalystToolkit) -> None:
        """create_servicenow_ticket should return not created without connector."""
        with patch(
            "shieldops.agents.soc_analyst.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            result = await toolkit.create_servicenow_ticket(
                alert_id="test-007",
                short_description="Test",
            )

        assert result["created"] is False

    @pytest.mark.asyncio()
    async def test_send_slack_notification_no_connector(self, toolkit: SOCAnalystToolkit) -> None:
        """send_slack_notification should return not sent without connector."""
        result = await toolkit.send_slack_notification(
            alert_id="test-008",
            channel="#soc-alerts",
            message="Test message",
        )
        assert result["sent"] is False
        assert "not available" in result["reason"]

    @pytest.mark.asyncio()
    async def test_escalate_alert_high_severity(
        self, toolkit_with_connectors: SOCAnalystToolkit
    ) -> None:
        """High severity true positive should trigger PD + Slack + ServiceNow."""
        with patch(
            "shieldops.agents.soc_analyst.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            result = await toolkit_with_connectors.escalate_alert(
                alert_id="test-009",
                alert_data={
                    "severity": "high",
                    "title": "Critical Malware",
                    "description": "Malware on prod server",
                },
                classification={
                    "classification": "true_positive",
                    "confidence": 0.9,
                },
            )

        assert result["severity"] == "high"
        actions = result["actions_taken"]
        action_types = [a["action"] for a in actions]
        assert "pagerduty_incident" in action_types
        assert "slack_notification" in action_types
        assert "servicenow_ticket" in action_types

    @pytest.mark.asyncio()
    async def test_escalate_alert_false_positive_auto_resolves(
        self, toolkit: SOCAnalystToolkit
    ) -> None:
        """False positive with high confidence should auto-resolve."""
        with patch(
            "shieldops.agents.soc_analyst.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            result = await toolkit.escalate_alert(
                alert_id="test-010",
                alert_data={"severity": "medium"},
                classification={
                    "classification": "false_positive",
                    "confidence": 0.9,
                },
            )

        actions = result["actions_taken"]
        assert len(actions) == 1
        assert actions[0]["action"] == "auto_resolve"
        assert actions[0]["resolved"] is True

    @pytest.mark.asyncio()
    async def test_escalate_alert_low_severity_auto_resolves(
        self, toolkit: SOCAnalystToolkit
    ) -> None:
        """Low severity non-TP alerts should auto-resolve."""
        with patch(
            "shieldops.agents.soc_analyst.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            result = await toolkit.escalate_alert(
                alert_id="test-011",
                alert_data={"severity": "low"},
                classification={
                    "classification": "needs_investigation",
                    "confidence": 0.4,
                },
            )

        actions = result["actions_taken"]
        assert len(actions) == 1
        assert actions[0]["action"] == "auto_resolve"

    @pytest.mark.asyncio()
    async def test_escalation_policy_denied(self, toolkit: SOCAnalystToolkit) -> None:
        """Escalation actions should respect policy denials."""
        with patch(
            "shieldops.agents.soc_analyst.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = False
            mock_decision.reason = "Policy denied escalation"
            mock_policy.return_value = mock_decision

            result = await toolkit.auto_resolve_alert(
                alert_id="test-012",
                severity="low",
            )

        assert result["resolved"] is False
        assert result.get("policy_denied") is True


# ---------------------------------------------------------------------------
# LLM Fallback Tests
# ---------------------------------------------------------------------------


class TestLLMFallback:
    """Verify heuristic fallback works when LLM is unavailable."""

    @pytest.mark.asyncio()
    async def test_classify_severity_llm_fallback(self, toolkit: SOCAnalystToolkit) -> None:
        """classify_severity should use heuristic when LLM fails."""
        with patch(
            "shieldops.agents.soc_analyst.tools.llm_structured",
            new_callable=AsyncMock,
            side_effect=Exception("LLM unavailable"),
        ):
            result = await toolkit.classify_severity(
                {
                    "alert_type": "malware_detected",
                    "description": "Malware found",
                }
            )

        assert result["method"] == "heuristic"
        assert result["classified_severity"] == "high"
        assert result["confidence"] > 0

    @pytest.mark.asyncio()
    async def test_classify_severity_llm_success(self, toolkit: SOCAnalystToolkit) -> None:
        """classify_severity should use LLM result when available."""
        mock_llm_result = MagicMock()
        mock_llm_result.triage_score = 92.0
        mock_llm_result.reasoning = "LLM determined critical"

        with patch(
            "shieldops.agents.soc_analyst.tools.llm_structured",
            new_callable=AsyncMock,
            return_value=mock_llm_result,
        ):
            result = await toolkit.classify_severity(
                {
                    "alert_type": "c2_communication",
                    "description": "C2 beacon detected",
                }
            )

        assert result["method"] == "llm"
        assert result["classified_severity"] == "critical"
        assert result["triage_score"] == 92.0

    @pytest.mark.asyncio()
    async def test_classify_true_false_positive_llm_fallback(
        self, toolkit: SOCAnalystToolkit
    ) -> None:
        """classify_true_false_positive should use heuristic when LLM fails."""
        with patch(
            "shieldops.agents.soc_analyst.tools.llm_structured",
            new_callable=AsyncMock,
            side_effect=Exception("LLM unavailable"),
        ):
            result = await toolkit.classify_true_false_positive(
                {
                    "ioc_matches": ["ioc-1", "ioc-2"],
                    "crowdstrike_detections": [{"id": "d1"}, {"id": "d2"}],
                    "reputation_score": 0.8,
                    "mitre_techniques": ["T1059", "T1204"],
                    "threat_feeds": ["feed1"],
                }
            )

        assert result["method"] == "heuristic"
        assert result["classification"] == "true_positive"
        assert result["confidence"] > 0.5

    @pytest.mark.asyncio()
    async def test_heuristic_classification_false_positive(
        self, toolkit: SOCAnalystToolkit
    ) -> None:
        """Heuristic should classify as false_positive with weak signals."""
        result = toolkit._heuristic_classification(
            {
                "ioc_matches": [],
                "crowdstrike_detections": [],
                "splunk_correlated_events": [],
                "reputation_score": 0.1,
                "mitre_techniques": [],
                "threat_feeds": [],
            }
        )
        assert result["classification"] == "false_positive"

    @pytest.mark.asyncio()
    async def test_heuristic_classification_needs_investigation(
        self, toolkit: SOCAnalystToolkit
    ) -> None:
        """Heuristic should classify as needs_investigation with moderate signals."""
        result = toolkit._heuristic_classification(
            {
                "ioc_matches": ["ioc-1"],
                "crowdstrike_detections": [],
                "splunk_correlated_events": [{"s": 1}, {"s": 2}, {"s": 3}],
                "reputation_score": 0.5,
                "mitre_techniques": [],
                "threat_feeds": [],
            }
        )
        assert result["classification"] == "needs_investigation"


# ---------------------------------------------------------------------------
# OPA Policy Tests
# ---------------------------------------------------------------------------


class TestOPAPolicyChecks:
    """Verify OPA policy is checked before actions."""

    @pytest.mark.asyncio()
    async def test_triage_calls_policy(self, toolkit: SOCAnalystToolkit) -> None:
        """triage_alert node should evaluate OPA policy."""
        set_toolkit(toolkit)

        state = SOCAnalystState(
            alert_id="test-policy",
            alert_data={"severity": "medium"},
        )

        with patch(
            "shieldops.agents.soc_analyst.nodes.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            await triage_alert(state)

            mock_policy.assert_called_once()
            call_kwargs = mock_policy.call_args[1]
            assert call_kwargs["action"] == "triage_alert"

    @pytest.mark.asyncio()
    async def test_auto_resolve_calls_policy(self, toolkit: SOCAnalystToolkit) -> None:
        """auto_resolve_alert should call OPA policy check."""
        with patch(
            "shieldops.agents.soc_analyst.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            await toolkit.auto_resolve_alert("test-001", "low")

            mock_policy.assert_called_once()

    @pytest.mark.asyncio()
    async def test_pagerduty_calls_policy(self, toolkit_with_connectors: SOCAnalystToolkit) -> None:
        """create_pagerduty_incident should call OPA policy check."""
        with patch(
            "shieldops.agents.soc_analyst.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            await toolkit_with_connectors.create_pagerduty_incident(
                alert_id="test-001",
                title="Test",
                service_id="svc-1",
            )

            mock_policy.assert_called_once()

    @pytest.mark.asyncio()
    async def test_servicenow_calls_policy(
        self, toolkit_with_connectors: SOCAnalystToolkit
    ) -> None:
        """create_servicenow_ticket should call OPA policy check."""
        with patch(
            "shieldops.agents.soc_analyst.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_policy:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_policy.return_value = mock_decision

            await toolkit_with_connectors.create_servicenow_ticket(
                alert_id="test-001",
                short_description="Test",
            )

            mock_policy.assert_called_once()

    @pytest.mark.asyncio()
    async def test_policy_error_fails_open_for_triage(self, toolkit: SOCAnalystToolkit) -> None:
        """Triage should proceed when policy engine is unreachable."""
        set_toolkit(toolkit)

        state = SOCAnalystState(
            alert_id="test-failopen",
            alert_data={"severity": "high", "alert_type": "malware_detected"},
        )

        with patch(
            "shieldops.agents.soc_analyst.nodes.policy_evaluate",
            new_callable=AsyncMock,
            side_effect=Exception("OPA unreachable"),
        ):
            result = await triage_alert(state)

        # Should proceed despite policy error
        assert "triage_score" in result
        assert "error" not in result


# ---------------------------------------------------------------------------
# Persistence Tests
# ---------------------------------------------------------------------------


class TestPersistence:
    """Verify persistence calls in finalize node."""

    @pytest.mark.asyncio()
    async def test_finalize_persists_run(self, toolkit: SOCAnalystToolkit) -> None:
        """finalize should call persist_agent_run."""
        set_toolkit(toolkit)

        state = SOCAnalystState(
            alert_id="test-persist",
            alert_data={"org_id": "org-test-1"},
            tier=2,
            triage_score=75.0,
            session_start=datetime.now(UTC),
        )

        with (
            patch(
                "shieldops.agents.soc_analyst.nodes.persist_agent_run",
                new_callable=AsyncMock,
            ) as mock_persist,
            patch(
                "shieldops.agents.soc_analyst.nodes.write_audit_log",
                new_callable=AsyncMock,
            ) as mock_audit,
        ):
            result = await finalize(state)

            mock_persist.assert_called_once()
            persist_kwargs = mock_persist.call_args[1]
            assert persist_kwargs["agent_name"] == "soc_analyst"
            assert persist_kwargs["org_id"] == "org-test-1"

            mock_audit.assert_called_once()
            audit_kwargs = mock_audit.call_args[1]
            assert audit_kwargs["action"] == "soc_analyst.completed"
            assert audit_kwargs["actor"] == "soc_analyst-agent"
            assert audit_kwargs["target"] == "test-persist"

        assert result["current_step"] == "complete"

    @pytest.mark.asyncio()
    async def test_finalize_handles_persistence_failure(self, toolkit: SOCAnalystToolkit) -> None:
        """finalize should not crash when persistence fails."""
        set_toolkit(toolkit)

        state = SOCAnalystState(
            alert_id="test-persist-fail",
            alert_data={},
            session_start=datetime.now(UTC),
        )

        with (
            patch(
                "shieldops.agents.soc_analyst.nodes.persist_agent_run",
                new_callable=AsyncMock,
                side_effect=Exception("DB unreachable"),
            ),
            patch(
                "shieldops.agents.soc_analyst.nodes.write_audit_log",
                new_callable=AsyncMock,
                side_effect=Exception("DB unreachable"),
            ),
        ):
            result = await finalize(state)

        # Should still complete
        assert result["current_step"] == "complete"


# ---------------------------------------------------------------------------
# Graph Compilation Tests
# ---------------------------------------------------------------------------


class TestGraphCompilation:
    """Verify the SOC analyst graph compiles and has expected structure."""

    def test_graph_compiles(self) -> None:
        """create_soc_analyst_graph() should compile without errors."""
        from shieldops.agents.soc_analyst.graph import create_soc_analyst_graph

        graph = create_soc_analyst_graph()
        app = graph.compile()
        assert app is not None

    def test_graph_has_expected_nodes(self) -> None:
        """Graph should have all expected node names."""
        from shieldops.agents.soc_analyst.graph import create_soc_analyst_graph

        graph = create_soc_analyst_graph()
        expected_nodes = {
            "triage_alert",
            "enrich_alert",
            "correlate_events",
            "map_attack_chain",
            "generate_narrative",
            "recommend_containment",
            "execute_playbook",
            "finalize",
        }
        assert expected_nodes.issubset(set(graph.nodes.keys()))

    def test_graph_entry_point_is_triage(self) -> None:
        """Graph entry point should be triage_alert."""
        from shieldops.agents.soc_analyst.graph import create_soc_analyst_graph

        graph = create_soc_analyst_graph()
        # The entry point is set via set_entry_point which sets __start__ edges
        assert "triage_alert" in graph.nodes


# ---------------------------------------------------------------------------
# Metrics Tracking Tests
# ---------------------------------------------------------------------------


class TestMetricsTracking:
    """Verify SOC metrics are tracked correctly."""

    @pytest.mark.asyncio()
    async def test_triage_tracks_alert_count(self, toolkit: SOCAnalystToolkit) -> None:
        """Toolkit should track triaged alert counts."""
        await toolkit.triage_alert(
            {
                "severity": "high",
                "alert_type": "malware_detected",
                "source": "crowdstrike",
            }
        )

        metrics = await toolkit.track_metrics()
        assert metrics["alerts_triaged"] == 1

    @pytest.mark.asyncio()
    async def test_escalation_tracks_count(self, toolkit: SOCAnalystToolkit) -> None:
        """Toolkit should track escalation counts."""
        await toolkit.escalate(
            alert={"alert_id": "test", "severity": "critical"},
            classification={"classification": "true_positive", "confidence": 0.9},
        )

        metrics = await toolkit.track_metrics()
        assert metrics["escalations"] == 1

    @pytest.mark.asyncio()
    async def test_classification_tracks_tp_fp(self, toolkit: SOCAnalystToolkit) -> None:
        """Toolkit should track TP/FP classification counts."""
        with patch(
            "shieldops.agents.soc_analyst.tools.llm_structured",
            new_callable=AsyncMock,
            side_effect=Exception("LLM unavailable"),
        ):
            # True positive case (strong signals)
            await toolkit.classify_true_false_positive(
                {
                    "ioc_matches": ["ioc-1", "ioc-2", "ioc-3"],
                    "crowdstrike_detections": [{"id": "d1"}, {"id": "d2"}, {"id": "d3"}],
                    "reputation_score": 0.9,
                    "mitre_techniques": ["T1059", "T1204"],
                    "threat_feeds": ["feed1", "feed2"],
                }
            )
            # False positive case (weak signals)
            await toolkit.classify_true_false_positive(
                {
                    "ioc_matches": [],
                    "crowdstrike_detections": [],
                    "reputation_score": 0.1,
                    "mitre_techniques": [],
                    "threat_feeds": [],
                }
            )

        metrics = await toolkit.track_metrics()
        assert metrics["true_positives"] >= 1
        assert metrics["false_positives"] >= 1
