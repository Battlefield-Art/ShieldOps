"""Tests for Incident Response Agent full implementation.

Covers:
- Containment calls correct connector methods (CrowdStrike, AWS SG, K8s quarantine)
- Eradication revokes credentials via AWS IAM
- Timeline reconstructed from multi-source (Splunk, CrowdStrike, CloudTrail)
- OPA phase gates checked at each IR phase (contain, eradicate, recover)
- Graph compiles and includes all expected nodes
- Notification integration (PagerDuty, ServiceNow)
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.agents.incident_response.models import (
    ContainmentAction,
    EradicationStep,
    IncidentResponseState,
    RecoveryTask,
)
from shieldops.agents.incident_response.nodes import (
    build_timeline,
    execute_containment,
    notify_stakeholders,
    plan_eradication,
    plan_recovery,
    set_toolkit,
)
from shieldops.agents.incident_response.tools import IncidentResponseToolkit

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_connector_router() -> MagicMock:
    """Router that returns mock connectors for each provider."""
    crowdstrike = AsyncMock()
    crowdstrike.contain_host = AsyncMock(
        return_value={"status": "contained", "device_id": "host-001"}
    )
    crowdstrike.lift_containment = AsyncMock(
        return_value={"status": "lifted", "device_id": "host-001"}
    )
    crowdstrike.get_detections = AsyncMock(
        return_value=[
            {
                "created_timestamp": "2026-04-05T10:00:00Z",
                "behaviors": [{"tactic": "Execution", "user_name": "admin"}],
            }
        ]
    )
    crowdstrike._api_request = AsyncMock(return_value={"resources": [{"stdout": "process killed"}]})

    splunk = AsyncMock()
    splunk.search_spl = AsyncMock(
        return_value=[
            {
                "_time": "2026-04-05T09:50:00Z",
                "host": "host-001",
                "source": "syslog",
                "sourcetype": "linux:auth",
                "action": "login_failed",
                "user": "attacker",
                "src_ip": "10.0.0.99",
                "dest_ip": "10.0.0.1",
            },
        ]
    )

    aws = AsyncMock()
    aws._ensure_clients = MagicMock()
    aws._region = "us-east-1"
    aws._ec2_client = MagicMock()
    aws.get_events = AsyncMock(
        return_value=[
            {
                "event_id": "ct-001",
                "event_name": "StopInstances",
                "event_time": "2026-04-05T09:55:00Z",
                "username": "attacker-role",
                "resource_name": "i-0123456789",
            }
        ]
    )
    aws.get_health = AsyncMock()
    aws.get_health.return_value = MagicMock(healthy=True, status="running")

    k8s = AsyncMock()
    k8s._ensure_client = AsyncMock()
    k8s._core_api = AsyncMock()
    k8s._core_api.patch_namespaced_pod = AsyncMock()

    pagerduty = AsyncMock()
    pagerduty._routing_key = "test-routing-key"
    pagerduty.trigger_event = AsyncMock(
        return_value={"status": "success", "dedup_key": "dedup-001"}
    )

    servicenow = AsyncMock()
    servicenow.create_incident = AsyncMock(
        return_value={"sys_id": "INC0001234", "number": "INC0001234"}
    )

    connectors = {
        "crowdstrike": crowdstrike,
        "splunk": splunk,
        "aws": aws,
        "kubernetes": k8s,
        "pagerduty": pagerduty,
        "servicenow": servicenow,
    }

    router = MagicMock()
    router.get = MagicMock(side_effect=lambda p: connectors.get(p))
    return router


@pytest.fixture()
def toolkit(mock_connector_router: MagicMock) -> IncidentResponseToolkit:
    """Toolkit wired with mock connectors."""
    tk = IncidentResponseToolkit(connector_router=mock_connector_router)
    set_toolkit(tk)
    return tk


@pytest.fixture()
def incident_state() -> IncidentResponseState:
    """Populated incident state for testing nodes."""
    return IncidentResponseState(
        incident_id="INC-2026-001",
        incident_data={
            "type": "malware",
            "severity": "critical",
            "affected_host": "host-001",
            "affected_hosts": ["host-001"],
            "affected_services": ["api-server", "auth-service"],
            "iocs": ["192.168.1.100", "evil.exe"],
            "malware_detected": True,
            "malware_process": "evil.exe",
            "namespace": "production",
            "vpc_id": "vpc-abc123",
        },
        severity="critical",
        assessment_score=95.0,
        incident_type="malware",
    )


# ---------------------------------------------------------------------------
# Containment Tests
# ---------------------------------------------------------------------------


class TestContainment:
    """Containment calls correct connector methods."""

    @pytest.mark.asyncio
    async def test_crowdstrike_network_isolation(
        self, toolkit: IncidentResponseToolkit, mock_connector_router: MagicMock
    ) -> None:
        """CrowdStrike contain_host is called for network_isolation."""
        result = await toolkit.execute_containment("network_isolation", "host-001")

        assert result["status"] == "completed"
        assert result["connector_used"] is True
        cs = mock_connector_router.get("crowdstrike")
        cs.contain_host.assert_awaited_once_with("host-001")

    @pytest.mark.asyncio
    async def test_aws_sg_isolation(
        self, toolkit: IncidentResponseToolkit, mock_connector_router: MagicMock
    ) -> None:
        """AWS SG isolation creates and applies restrictive security group."""
        aws = mock_connector_router.get("aws")
        # Mock the EC2 describe call
        aws._ec2_client.describe_instances = MagicMock(
            return_value={
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "VpcId": "vpc-abc123",
                                "SecurityGroups": [{"GroupId": "sg-old"}],
                            }
                        ]
                    }
                ]
            }
        )
        aws._ec2_client.create_security_group = MagicMock(
            return_value={"GroupId": "sg-isolate-001"}
        )
        aws._ec2_client.revoke_security_group_egress = MagicMock()
        aws._ec2_client.modify_instance_attribute = MagicMock()

        result = await toolkit.isolate_aws_security_group("i-001", "vpc-abc123")

        assert result["status"] == "completed"
        assert result["connector_used"] is True
        assert result["details"]["security_group_id"] == "sg-isolate-001"

    @pytest.mark.asyncio
    async def test_k8s_quarantine(
        self, toolkit: IncidentResponseToolkit, mock_connector_router: MagicMock
    ) -> None:
        """K8s quarantine labels the pod and creates NetworkPolicy."""
        mock_net_api = AsyncMock()
        mock_net_api.create_namespaced_network_policy = AsyncMock()

        # Patch NetworkingV1Api in the kubernetes_asyncio.client module
        with (
            patch(
                "kubernetes_asyncio.client.NetworkingV1Api",
                return_value=mock_net_api,
                create=True,
            ),
            patch(
                "kubernetes_asyncio.client.V1NetworkPolicy",
                return_value=MagicMock(),
                create=True,
            ),
            patch(
                "kubernetes_asyncio.client.V1ObjectMeta",
                return_value=MagicMock(),
                create=True,
            ),
            patch(
                "kubernetes_asyncio.client.V1NetworkPolicySpec",
                return_value=MagicMock(),
                create=True,
            ),
            patch(
                "kubernetes_asyncio.client.V1LabelSelector",
                return_value=MagicMock(),
                create=True,
            ),
        ):
            result = await toolkit.quarantine_k8s_pod(
                namespace="production",
                pod_name="evil-pod-abc",
            )

        assert result["status"] == "completed"
        assert result["connector_used"] is True
        k8s = mock_connector_router.get("kubernetes")
        k8s._core_api.patch_namespaced_pod.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_containment_without_connectors(self) -> None:
        """Containment falls back gracefully when connectors unavailable."""
        tk = IncidentResponseToolkit()
        set_toolkit(tk)

        result = await tk.execute_containment("network_isolation", "host-001")
        assert result["status"] == "completed_with_fallback"
        assert result["connector_used"] is False
        assert result["details"]["manual_action_required"] is True

    @pytest.mark.asyncio
    async def test_execute_containment_node_calls_phase_gate(
        self, toolkit: IncidentResponseToolkit, incident_state: IncidentResponseState
    ) -> None:
        """Execute containment node evaluates OPA phase gate."""
        incident_state.containment_actions = [
            ContainmentAction(
                action_id="c-001",
                action_type="network_isolation",
                target="host-001",
                automated=True,
            )
        ]

        with patch(
            "shieldops.agents.incident_response.tools.evaluate",
            new_callable=AsyncMock,
        ) as mock_evaluate:
            from shieldops.policy.engine import Decision, PolicyDecision

            mock_evaluate.return_value = PolicyDecision(
                allowed=True,
                decision=Decision.APPROVED,
                reason="Auto-approved: risk score below threshold.",
            )

            result = await execute_containment(incident_state)

        assert "phase_gate_results" in result
        assert "contain" in result["phase_gate_results"]
        assert result["phase_gate_results"]["contain"]["allowed"] is True


# ---------------------------------------------------------------------------
# Eradication Tests
# ---------------------------------------------------------------------------


class TestEradication:
    """Eradication executes correct actions via connectors."""

    @pytest.mark.asyncio
    async def test_credential_rotation_via_aws(
        self, toolkit: IncidentResponseToolkit, mock_connector_router: MagicMock
    ) -> None:
        """Credential rotation deactivates IAM access keys."""
        with patch("boto3.Session") as mock_session:
            mock_iam = MagicMock()
            mock_iam.list_access_keys = MagicMock(
                return_value={
                    "AccessKeyMetadata": [
                        {"AccessKeyId": "AKIA123", "Status": "Active"},
                    ]
                }
            )
            mock_iam.update_access_key = MagicMock()
            mock_session.return_value.client.return_value = mock_iam

            result = await toolkit.execute_eradication(
                step_type="credential_rotation",
                target="compromised-user",
            )

        assert result["status"] == "completed"
        assert result["connector_used"] is True
        assert "AKIA123" in result["details"]["deactivated_keys"]

    @pytest.mark.asyncio
    async def test_process_kill_via_crowdstrike(
        self, toolkit: IncidentResponseToolkit, mock_connector_router: MagicMock
    ) -> None:
        """Process termination uses CrowdStrike RTR."""
        result = await toolkit.execute_eradication(
            step_type="process_termination",
            target="host-001",
        )

        assert result["connector_used"] is True
        cs = mock_connector_router.get("crowdstrike")
        cs._api_request.assert_awaited()

    @pytest.mark.asyncio
    async def test_ioc_removal_via_crowdstrike(
        self, toolkit: IncidentResponseToolkit, mock_connector_router: MagicMock
    ) -> None:
        """IOC removal uses CrowdStrike RTR to delete files."""
        result = await toolkit.execute_eradication(
            step_type="ioc_removal",
            target="host-001",
        )

        assert result["connector_used"] is True

    @pytest.mark.asyncio
    async def test_eradication_node_checks_phase_gate(
        self, toolkit: IncidentResponseToolkit, incident_state: IncidentResponseState
    ) -> None:
        """Plan eradication node evaluates OPA phase gate."""
        with patch(
            "shieldops.agents.incident_response.tools.evaluate",
            new_callable=AsyncMock,
        ) as mock_evaluate:
            from shieldops.policy.engine import Decision, PolicyDecision

            mock_evaluate.return_value = PolicyDecision(
                allowed=True,
                decision=Decision.APPROVED,
                reason="Auto-approved.",
            )

            result = await plan_eradication(incident_state)

        assert "phase_gate_results" in result
        assert "eradicate" in result["phase_gate_results"]
        assert result["eradication_complete"] is True


# ---------------------------------------------------------------------------
# Recovery Tests
# ---------------------------------------------------------------------------


class TestRecovery:
    """Recovery executes restore and health checks."""

    @pytest.mark.asyncio
    async def test_uncontain_host(
        self, toolkit: IncidentResponseToolkit, mock_connector_router: MagicMock
    ) -> None:
        """Uncontain host calls CrowdStrike lift_containment."""
        result = await toolkit.execute_restore(
            service="host-001",
            task_type="uncontain_host",
        )

        assert result["status"] == "completed"
        assert result["connector_used"] is True
        cs = mock_connector_router.get("crowdstrike")
        cs.lift_containment.assert_awaited_once_with("host-001")

    @pytest.mark.asyncio
    async def test_health_validation_via_connector(
        self, toolkit: IncidentResponseToolkit, mock_connector_router: MagicMock
    ) -> None:
        """Health validation queries available connectors."""
        # Ensure get_health returns a proper object with .healthy and .status
        from shieldops.models.base import HealthStatus

        health = HealthStatus(
            resource_id="host-001",
            healthy=True,
            status="running",
            last_checked=datetime.now(UTC),
        )
        mock_connector_router.get("crowdstrike").get_health = AsyncMock(return_value=health)

        result = await toolkit.execute_restore(
            service="host-001",
            task_type="health_validation",
        )

        assert result["connector_used"] is True
        assert result["details"]["healthy"] is True

    @pytest.mark.asyncio
    async def test_recovery_node_checks_phase_gate(
        self, toolkit: IncidentResponseToolkit, incident_state: IncidentResponseState
    ) -> None:
        """Plan recovery node evaluates OPA phase gate."""
        with patch(
            "shieldops.agents.incident_response.tools.evaluate",
            new_callable=AsyncMock,
        ) as mock_evaluate:
            from shieldops.policy.engine import Decision, PolicyDecision

            mock_evaluate.return_value = PolicyDecision(
                allowed=True,
                decision=Decision.APPROVED,
                reason="Auto-approved.",
            )

            result = await plan_recovery(incident_state)

        assert "phase_gate_results" in result
        assert "recover" in result["phase_gate_results"]


# ---------------------------------------------------------------------------
# Timeline Tests
# ---------------------------------------------------------------------------


class TestTimeline:
    """Timeline reconstruction from multi-source data."""

    @pytest.mark.asyncio
    async def test_multi_source_timeline(
        self, toolkit: IncidentResponseToolkit, mock_connector_router: MagicMock
    ) -> None:
        """Timeline includes events from Splunk, CrowdStrike, and CloudTrail."""
        result = await toolkit.build_investigation_timeline(
            {
                "incident_id": "INC-001",
                "affected_host": "host-001",
                "timeframe": "-24h",
            }
        )

        assert result["event_count"] > 0
        sources = result["sources_queried"]
        assert "splunk" in sources
        assert "crowdstrike" in sources
        assert "cloudtrail" in sources
        assert "shieldops_ir" in sources

        # Verify events are sorted chronologically
        timestamps = [e["timestamp"] for e in result["events"] if e["timestamp"]]
        assert timestamps == sorted(timestamps)

    @pytest.mark.asyncio
    async def test_timeline_node_with_llm_fallback(
        self, toolkit: IncidentResponseToolkit, incident_state: IncidentResponseState
    ) -> None:
        """Build timeline node falls back to heuristic when LLM unavailable."""
        with patch(
            "shieldops.agents.incident_response.nodes.llm_structured",
            side_effect=Exception("LLM unavailable"),
        ):
            result = await build_timeline(incident_state)

        assert "timeline" in result
        timeline = result["timeline"]
        assert "summary" in timeline
        assert "key_findings" in timeline
        assert len(timeline["key_findings"]) > 0

    @pytest.mark.asyncio
    async def test_timeline_without_connectors(self) -> None:
        """Timeline includes only internal events when connectors unavailable."""
        tk = IncidentResponseToolkit()
        set_toolkit(tk)

        # Generate some internal timeline events first
        await tk.assess_incident({"type": "test", "severity": "low"})

        result = await tk.build_investigation_timeline(
            {"incident_id": "INC-002", "affected_host": "host-002"}
        )

        assert result["event_count"] > 0
        assert "shieldops_ir" in result["sources_queried"]


# ---------------------------------------------------------------------------
# Phase Gate Tests
# ---------------------------------------------------------------------------


class TestPhaseGates:
    """OPA policy evaluation at each IR phase."""

    @pytest.mark.asyncio
    async def test_contain_phase_gate_approved(self, toolkit: IncidentResponseToolkit) -> None:
        """Contain phase gate approves low-risk action."""
        with patch(
            "shieldops.agents.incident_response.tools.evaluate",
            new_callable=AsyncMock,
        ) as mock_evaluate:
            from shieldops.policy.engine import Decision, PolicyDecision

            mock_evaluate.return_value = PolicyDecision(
                allowed=True,
                decision=Decision.APPROVED,
                reason="Auto-approved.",
            )

            result = await toolkit.evaluate_phase_gate(
                phase="contain",
                incident_id="INC-001",
                severity="medium",
            )

        assert result["allowed"] is True
        assert result["phase"] == "contain"
        mock_evaluate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_eradicate_phase_gate_denied(self, toolkit: IncidentResponseToolkit) -> None:
        """Eradicate phase gate blocks when policy denies."""
        with patch(
            "shieldops.agents.incident_response.tools.evaluate",
            new_callable=AsyncMock,
        ) as mock_evaluate:
            from shieldops.policy.engine import Decision, PolicyDecision

            mock_evaluate.return_value = PolicyDecision(
                allowed=False,
                decision=Decision.DENIED,
                reason="Blast radius too large.",
            )

            result = await toolkit.evaluate_phase_gate(
                phase="eradicate",
                incident_id="INC-001",
                severity="critical",
            )

        assert result["allowed"] is False
        assert result["decision"] == "denied"

    @pytest.mark.asyncio
    async def test_phase_gate_fail_open_on_error(self, toolkit: IncidentResponseToolkit) -> None:
        """Phase gate fails open for IR when OPA is unreachable."""
        with patch(
            "shieldops.agents.incident_response.tools.evaluate",
            side_effect=Exception("OPA unreachable"),
        ):
            result = await toolkit.evaluate_phase_gate(
                phase="contain",
                incident_id="INC-001",
                severity="critical",
            )

        assert result["allowed"] is True
        assert "fail-open" in result["reason"]

    @pytest.mark.asyncio
    async def test_all_phases_checked_in_full_run(
        self, toolkit: IncidentResponseToolkit, incident_state: IncidentResponseState
    ) -> None:
        """Full workflow checks phase gates at contain, eradicate, and recover."""
        incident_state.containment_actions = [
            ContainmentAction(
                action_id="c-001",
                action_type="network_isolation",
                target="host-001",
                automated=True,
            )
        ]

        with patch(
            "shieldops.agents.incident_response.tools.evaluate",
            new_callable=AsyncMock,
        ) as mock_evaluate:
            from shieldops.policy.engine import Decision, PolicyDecision

            mock_evaluate.return_value = PolicyDecision(
                allowed=True,
                decision=Decision.APPROVED,
                reason="Auto-approved.",
            )

            # Run containment
            r1 = await execute_containment(incident_state)
            assert "contain" in r1["phase_gate_results"]

            # Update state for eradication
            incident_state.phase_gate_results = r1["phase_gate_results"]
            r2 = await plan_eradication(incident_state)
            assert "eradicate" in r2["phase_gate_results"]

            # Update state for recovery
            incident_state.phase_gate_results = r2["phase_gate_results"]
            r3 = await plan_recovery(incident_state)
            assert "recover" in r3["phase_gate_results"]

            # All three phases evaluated
            assert mock_evaluate.await_count == 3


# ---------------------------------------------------------------------------
# Notification Tests
# ---------------------------------------------------------------------------


class TestNotification:
    """Notification integration tests."""

    @pytest.mark.asyncio
    async def test_pagerduty_notification(
        self, toolkit: IncidentResponseToolkit, mock_connector_router: MagicMock
    ) -> None:
        """PagerDuty trigger_event is called for notifications."""
        result = await toolkit.notify_stakeholders(
            {
                "incident_id": "INC-001",
                "severity": "critical",
                "type": "malware",
            }
        )

        assert result["notification_status"] in ("completed", "partial")
        pd = mock_connector_router.get("pagerduty")
        pd.trigger_event.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_servicenow_ticket_creation(
        self, toolkit: IncidentResponseToolkit, mock_connector_router: MagicMock
    ) -> None:
        """ServiceNow incident ticket is created."""
        result = await toolkit.create_servicenow_ticket(
            {
                "incident_id": "INC-001",
                "severity": "critical",
                "type": "malware",
            }
        )

        assert result["status"] == "created"
        snow = mock_connector_router.get("servicenow")
        snow.create_incident.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_notify_stakeholders_node(
        self, toolkit: IncidentResponseToolkit, incident_state: IncidentResponseState
    ) -> None:
        """Notify stakeholders node sends notifications and creates ticket."""
        result = await notify_stakeholders(incident_state)

        assert "notification_results" in result
        assert "servicenow" in result["notification_results"]


# ---------------------------------------------------------------------------
# Graph Tests
# ---------------------------------------------------------------------------


class TestGraph:
    """Graph compilation and structure tests."""

    def test_graph_compiles(self) -> None:
        """Incident response graph compiles without errors."""
        from shieldops.agents.incident_response.graph import create_incident_response_graph

        graph = create_incident_response_graph()
        app = graph.compile()
        assert app is not None

    def test_graph_has_all_nodes(self) -> None:
        """Graph includes all expected nodes."""
        from shieldops.agents.incident_response.graph import create_incident_response_graph

        graph = create_incident_response_graph()

        expected_nodes = {
            "assess_incident",
            "plan_containment",
            "execute_containment",
            "plan_eradication",
            "plan_recovery",
            "validate_response",
            "notify_stakeholders",
            "build_timeline",
            "finalize_response",
        }

        # LangGraph stores nodes in the graph's nodes dict
        actual_nodes = set(graph.nodes.keys())
        assert expected_nodes.issubset(actual_nodes), (
            f"Missing nodes: {expected_nodes - actual_nodes}"
        )


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------


class TestModels:
    """State and model tests."""

    def test_state_defaults(self) -> None:
        """IncidentResponseState has correct defaults."""
        state = IncidentResponseState()
        assert state.error == ""
        assert state.incident_id == ""
        assert state.phase_gate_results == {}
        assert state.notification_results == {}
        assert state.timeline == {}
        assert state.containment_actions == []
        assert state.eradication_steps == []
        assert state.recovery_tasks == []

    def test_containment_action_model(self) -> None:
        """ContainmentAction initializes correctly."""
        action = ContainmentAction(
            action_id="c-001",
            action_type="network_isolation",
            target="host-001",
            automated=True,
        )
        assert action.status == "pending"
        assert action.risk_level == "medium"

    def test_eradication_step_model(self) -> None:
        """EradicationStep initializes correctly."""
        step = EradicationStep(
            step_id="e-001",
            step_type="credential_rotation",
            target="user-001",
            description="Rotate compromised creds",
        )
        assert step.status == "pending"

    def test_recovery_task_model(self) -> None:
        """RecoveryTask initializes correctly."""
        task = RecoveryTask(
            task_id="r-001",
            task_type="service_restart",
            service="api-server",
            priority="high",
            estimated_duration_min=15,
        )
        assert task.status == "pending"
