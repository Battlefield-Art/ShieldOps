"""Behavioral tests for the IncidentResponseToolkit."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from shieldops.agents.incident_response.tools import IncidentResponseToolkit

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_crowdstrike() -> AsyncMock:
    cs = AsyncMock()
    cs.contain_host = AsyncMock(
        return_value={"resources": [{"id": "dev-001", "status": "contained"}]}
    )
    return cs


@pytest.fixture
def mock_splunk() -> AsyncMock:
    splunk = AsyncMock()
    splunk.search_spl = AsyncMock(
        return_value=[
            {
                "_time": "2026-04-04T10:00:00Z",
                "host": "web-01",
                "source": "/var/log/auth.log",
                "sourcetype": "syslog",
                "action": "failed_login",
                "user": "admin",
                "src_ip": "10.0.0.99",
                "dest_ip": "10.0.1.5",
            },
        ]
    )
    return splunk


@pytest.fixture
def mock_pagerduty() -> AsyncMock:
    pd = AsyncMock()
    pd._routing_key = "test-routing-key"
    pd.trigger_event = AsyncMock(
        return_value={"status": "success", "dedup_key": "dedup-123", "message": "Event processed"}
    )
    return pd


@pytest.fixture
def router_with_connectors(
    mock_crowdstrike: AsyncMock,
    mock_splunk: AsyncMock,
    mock_pagerduty: AsyncMock,
) -> MagicMock:
    """ConnectorRouter mock with all three connectors registered."""
    router = MagicMock()

    def get_connector(provider: str) -> Any:
        connectors = {
            "crowdstrike": mock_crowdstrike,
            "splunk": mock_splunk,
            "pagerduty": mock_pagerduty,
        }
        if provider not in connectors:
            raise ValueError(f"No connector for {provider}")
        return connectors[provider]

    router.get = MagicMock(side_effect=get_connector)
    return router


@pytest.fixture
def toolkit_with_connectors(router_with_connectors: MagicMock) -> IncidentResponseToolkit:
    return IncidentResponseToolkit(connector_router=router_with_connectors)


@pytest.fixture
def toolkit_no_connectors() -> IncidentResponseToolkit:
    return IncidentResponseToolkit()


# ---------------------------------------------------------------------------
# assess_incident
# ---------------------------------------------------------------------------


class TestAssessIncident:
    @pytest.mark.asyncio
    async def test_returns_severity_and_score(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        result = await toolkit_no_connectors.assess_incident(
            {"type": "malware", "severity": "high"}
        )
        assert "severity" in result
        assert "assessment_score" in result
        assert isinstance(result["assessment_score"], float)
        assert result["incident_type"] == "malware"

    @pytest.mark.asyncio
    async def test_critical_severity_high_score(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        result = await toolkit_no_connectors.assess_incident(
            {
                "type": "ransomware",
                "severity": "critical",
                "affected_hosts": ["h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10"],
                "iocs": ["ioc1", "ioc2", "ioc3"],
            }
        )
        assert result["severity"] == "critical"
        assert result["assessment_score"] >= 80.0
        assert result["recommended_priority"] == "P1"

    @pytest.mark.asyncio
    async def test_low_severity_low_score(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        result = await toolkit_no_connectors.assess_incident({"type": "info", "severity": "low"})
        assert result["assessment_score"] < 50.0

    @pytest.mark.asyncio
    async def test_blast_radius_computed(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        result = await toolkit_no_connectors.assess_incident(
            {"type": "malware", "severity": "medium", "affected_hosts": ["h1", "h2"]}
        )
        assert "blast_radius" in result
        assert 0.0 <= result["blast_radius"] <= 1.0

    @pytest.mark.asyncio
    async def test_affected_systems_deduplication(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        result = await toolkit_no_connectors.assess_incident(
            {
                "type": "malware",
                "severity": "medium",
                "affected_host": "web-01",
                "affected_hosts": ["web-01", "db-01"],
                "affected_services": ["api-svc"],
            }
        )
        # web-01 appears twice in input but should be deduplicated
        assert len(result["affected_systems"]) == 3


# ---------------------------------------------------------------------------
# execute_containment
# ---------------------------------------------------------------------------


class TestExecuteContainment:
    @pytest.mark.asyncio
    async def test_network_isolation_with_crowdstrike(
        self,
        toolkit_with_connectors: IncidentResponseToolkit,
        mock_crowdstrike: AsyncMock,
    ) -> None:
        result = await toolkit_with_connectors.execute_containment(
            "network_isolation", "device-abc"
        )
        assert result["status"] == "completed"
        assert result["connector_used"] is True
        mock_crowdstrike.contain_host.assert_awaited_once_with("device-abc")

    @pytest.mark.asyncio
    async def test_network_isolation_fallback_without_connector(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        result = await toolkit_no_connectors.execute_containment("network_isolation", "device-abc")
        assert result["status"] == "completed_with_fallback"
        assert result["details"]["manual_action_required"] is True

    @pytest.mark.asyncio
    async def test_network_isolation_fallback_on_api_error(
        self,
        toolkit_with_connectors: IncidentResponseToolkit,
        mock_crowdstrike: AsyncMock,
    ) -> None:
        mock_crowdstrike.contain_host.side_effect = RuntimeError("API timeout")
        result = await toolkit_with_connectors.execute_containment(
            "network_isolation", "device-abc"
        )
        assert result["status"] == "completed_with_fallback"
        assert result["details"]["fallback"] is True

    @pytest.mark.asyncio
    async def test_process_kill_action(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        result = await toolkit_no_connectors.execute_containment("process_kill", "evil.exe")
        assert result["status"] == "completed"
        assert result["details"]["action"] == "process_kill"

    @pytest.mark.asyncio
    async def test_generic_action(self, toolkit_no_connectors: IncidentResponseToolkit) -> None:
        result = await toolkit_no_connectors.execute_containment("custom_block", "target-x")
        assert result["status"] == "completed"
        assert result["action_type"] == "custom_block"


# ---------------------------------------------------------------------------
# collect_evidence
# ---------------------------------------------------------------------------


class TestCollectEvidence:
    @pytest.mark.asyncio
    async def test_splunk_evidence_collection(
        self,
        toolkit_with_connectors: IncidentResponseToolkit,
        mock_splunk: AsyncMock,
    ) -> None:
        result = await toolkit_with_connectors.collect_evidence(
            {"incident_id": "INC-001", "affected_host": "web-01", "type": "malware"}
        )
        assert result["source"] == "splunk"
        assert result["evidence_count"] == 1
        assert result["evidence"][0]["host"] == "web-01"
        mock_splunk.search_spl.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_fallback_evidence_without_splunk(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        result = await toolkit_no_connectors.collect_evidence(
            {"incident_id": "INC-002", "affected_host": "db-01", "type": "unauthorized_access"}
        )
        assert result["source"] == "fallback"
        assert result["evidence_count"] >= 2  # at least 2 fallback items
        assert all("evidence_id" in e for e in result["evidence"])

    @pytest.mark.asyncio
    async def test_fallback_on_splunk_error(
        self,
        toolkit_with_connectors: IncidentResponseToolkit,
        mock_splunk: AsyncMock,
    ) -> None:
        mock_splunk.search_spl.side_effect = ConnectionError("Splunk unreachable")
        result = await toolkit_with_connectors.collect_evidence(
            {"incident_id": "INC-003", "affected_host": "app-01", "type": "malware"}
        )
        assert result["source"] == "fallback"
        assert result["evidence_count"] >= 1


# ---------------------------------------------------------------------------
# plan_eradication
# ---------------------------------------------------------------------------


class TestPlanEradication:
    @pytest.mark.asyncio
    async def test_malware_playbook(self, toolkit_no_connectors: IncidentResponseToolkit) -> None:
        steps = await toolkit_no_connectors.plan_eradication("malware")
        assert len(steps) == 3
        step_types = [s["step_type"] for s in steps]
        assert "process_termination" in step_types
        assert "ioc_removal" in step_types
        assert "credential_rotation" in step_types

    @pytest.mark.asyncio
    async def test_ransomware_playbook(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        steps = await toolkit_no_connectors.plan_eradication("ransomware")
        assert len(steps) == 4
        assert steps[0]["step_type"] == "network_isolation"

    @pytest.mark.asyncio
    async def test_unknown_type_generic_playbook(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        steps = await toolkit_no_connectors.plan_eradication("zero_day_exploit")
        assert len(steps) == 3
        assert all("step_id" in s for s in steps)
        assert all("description" in s for s in steps)

    @pytest.mark.asyncio
    async def test_steps_have_status(self, toolkit_no_connectors: IncidentResponseToolkit) -> None:
        steps = await toolkit_no_connectors.plan_eradication("phishing")
        assert all(s.get("status") == "pending" for s in steps)


# ---------------------------------------------------------------------------
# execute_recovery
# ---------------------------------------------------------------------------


class TestExecuteRecovery:
    @pytest.mark.asyncio
    async def test_restore_from_snapshot(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        result = await toolkit_no_connectors.execute_recovery("api-svc", "restore_from_snapshot")
        assert result["status"] == "completed"
        assert result["service"] == "api-svc"
        assert result["recovery_plan"]["estimated_duration_min"] == 30

    @pytest.mark.asyncio
    async def test_service_restart(self, toolkit_no_connectors: IncidentResponseToolkit) -> None:
        result = await toolkit_no_connectors.execute_recovery("web-svc", "service_restart")
        assert result["status"] == "completed"
        assert result["recovery_plan"]["estimated_duration_min"] == 10

    @pytest.mark.asyncio
    async def test_unknown_task_type(self, toolkit_no_connectors: IncidentResponseToolkit) -> None:
        result = await toolkit_no_connectors.execute_recovery("db-svc", "custom_restore")
        assert result["status"] == "completed"
        assert result["recovery_plan"]["task_type"] == "custom_restore"

    @pytest.mark.asyncio
    async def test_includes_validation_step(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        result = await toolkit_no_connectors.execute_recovery("api-svc", "service_restart")
        assert "validation" in result
        assert result["validation"]["status"] == "pending"
        assert "service_responding" in result["validation"]["checks"]


# ---------------------------------------------------------------------------
# validate_recovery
# ---------------------------------------------------------------------------


class TestValidateRecovery:
    @pytest.mark.asyncio
    async def test_validation_passes(self, toolkit_no_connectors: IncidentResponseToolkit) -> None:
        result = await toolkit_no_connectors.validate_recovery("INC-001")
        assert result["passed"] is True
        assert result["incident_id"] == "INC-001"
        assert "validated_at" in result

    @pytest.mark.asyncio
    async def test_all_checks_present(self, toolkit_no_connectors: IncidentResponseToolkit) -> None:
        result = await toolkit_no_connectors.validate_recovery("INC-002")
        expected_checks = {
            "service_health",
            "no_active_threats",
            "iocs_cleared",
            "credentials_rotated",
            "monitoring_restored",
        }
        assert set(result["checks"].keys()) == expected_checks


# ---------------------------------------------------------------------------
# notify_stakeholders
# ---------------------------------------------------------------------------


class TestNotifyStakeholders:
    @pytest.mark.asyncio
    async def test_pagerduty_notification_sent(
        self,
        toolkit_with_connectors: IncidentResponseToolkit,
        mock_pagerduty: AsyncMock,
    ) -> None:
        result = await toolkit_with_connectors.notify_stakeholders(
            {"incident_id": "INC-001", "severity": "critical", "type": "ransomware"}
        )
        assert result["notification_status"] == "completed"
        pd_notif = next(n for n in result["notifications"] if n["channel"] == "pagerduty")
        assert pd_notif["status"] == "sent"
        mock_pagerduty.trigger_event.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_pagerduty_skipped_without_connector(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        result = await toolkit_no_connectors.notify_stakeholders(
            {"incident_id": "INC-002", "severity": "high", "type": "malware"}
        )
        pd_notif = next(n for n in result["notifications"] if n["channel"] == "pagerduty")
        assert pd_notif["status"] == "skipped"

    @pytest.mark.asyncio
    async def test_slack_and_email_always_queued(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        result = await toolkit_no_connectors.notify_stakeholders(
            {"incident_id": "INC-003", "severity": "medium", "type": "phishing"}
        )
        channels = {n["channel"] for n in result["notifications"]}
        assert "slack" in channels
        assert "email" in channels

    @pytest.mark.asyncio
    async def test_pagerduty_failure_handled(
        self,
        toolkit_with_connectors: IncidentResponseToolkit,
        mock_pagerduty: AsyncMock,
    ) -> None:
        mock_pagerduty.trigger_event.side_effect = RuntimeError("PD API error")
        result = await toolkit_with_connectors.notify_stakeholders(
            {"incident_id": "INC-004", "severity": "high", "type": "malware"}
        )
        pd_notif = next(n for n in result["notifications"] if n["channel"] == "pagerduty")
        assert pd_notif["status"] == "failed"
        # Should not crash; other notifications still present
        assert len(result["notifications"]) == 3


# ---------------------------------------------------------------------------
# generate_timeline
# ---------------------------------------------------------------------------


class TestGenerateTimeline:
    @pytest.mark.asyncio
    async def test_empty_timeline(self, toolkit_no_connectors: IncidentResponseToolkit) -> None:
        result = await toolkit_no_connectors.generate_timeline()
        assert result["event_count"] == 0
        assert result["timeline"] == []
        assert "generated_at" in result

    @pytest.mark.asyncio
    async def test_timeline_populated_after_actions(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        await toolkit_no_connectors.assess_incident({"type": "malware", "severity": "high"})
        await toolkit_no_connectors.execute_containment("process_kill", "evil.exe")
        await toolkit_no_connectors.collect_evidence(
            {"incident_id": "INC-001", "affected_host": "web-01", "type": "malware"}
        )

        result = await toolkit_no_connectors.generate_timeline()
        assert result["event_count"] == 3
        actions = [e["action"] for e in result["timeline"]]
        assert "assess_incident" in actions
        assert "contain_threat" in actions
        assert "collect_evidence" in actions

    @pytest.mark.asyncio
    async def test_timeline_sorted_by_timestamp(
        self, toolkit_no_connectors: IncidentResponseToolkit
    ) -> None:
        await toolkit_no_connectors.assess_incident({"type": "phishing", "severity": "medium"})
        await toolkit_no_connectors.plan_eradication("phishing")

        result = await toolkit_no_connectors.generate_timeline()
        timestamps = [e["timestamp"] for e in result["timeline"]]
        assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# record_response_metric
# ---------------------------------------------------------------------------


class TestRecordResponseMetric:
    @pytest.mark.asyncio
    async def test_metric_recorded(self, toolkit_no_connectors: IncidentResponseToolkit) -> None:
        # Should not raise
        await toolkit_no_connectors.record_response_metric("assessment", 85.0)

        timeline = await toolkit_no_connectors.generate_timeline()
        assert timeline["event_count"] == 1
        assert timeline["timeline"][0]["action"] == "record_metric"


# ---------------------------------------------------------------------------
# End-to-end: full IR lifecycle
# ---------------------------------------------------------------------------


class TestFullLifecycle:
    @pytest.mark.asyncio
    async def test_full_incident_response_workflow(
        self, toolkit_with_connectors: IncidentResponseToolkit
    ) -> None:
        """Run a complete IR lifecycle and verify timeline captures all phases."""
        # 1. Assess
        assessment = await toolkit_with_connectors.assess_incident(
            {
                "type": "ransomware",
                "severity": "critical",
                "affected_hosts": [f"web-{i:02d}" for i in range(10)],
                "iocs": ["hash-abc", "ip-1.2.3.4", "domain-evil.com"],
            }
        )
        assert assessment["severity"] == "critical"

        # 2. Contain
        containment = await toolkit_with_connectors.execute_containment(
            "network_isolation", "web-01"
        )
        assert containment["status"] == "completed"

        # 3. Collect evidence
        evidence = await toolkit_with_connectors.collect_evidence(
            {"incident_id": "INC-100", "affected_host": "web-01", "type": "ransomware"}
        )
        assert evidence["evidence_count"] >= 1

        # 4. Eradicate
        eradication = await toolkit_with_connectors.plan_eradication("ransomware")
        assert len(eradication) == 4

        # 5. Recover
        recovery = await toolkit_with_connectors.execute_recovery("web-01", "restore_from_snapshot")
        assert recovery["status"] == "completed"

        # 6. Validate
        validation = await toolkit_with_connectors.validate_recovery("INC-100")
        assert validation["passed"] is True

        # 7. Notify
        notification = await toolkit_with_connectors.notify_stakeholders(
            {"incident_id": "INC-100", "severity": "critical", "type": "ransomware"}
        )
        assert notification["notification_status"] == "completed"

        # 8. Timeline
        timeline = await toolkit_with_connectors.generate_timeline()
        assert timeline["event_count"] >= 7
