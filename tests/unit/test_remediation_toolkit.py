"""Tests for RemediationToolkit production enhancements.

Covers:
- OPA approval workflow (auto-approve / human-approval / escalate)
- Blast-radius limits per environment (dev=10, staging=5, prod=3)
- CrowdStrike containment with mock connector + poll verification
- ServiceNow ticket creation
- Audit trail logging
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from shieldops.agents.remediation.tools import (
    BLAST_RADIUS_LIMITS,
    BlastRadiusExceeded,
    RemediationToolkit,
)
from shieldops.models.base import (
    ApprovalStatus,
    Environment,
    ExecutionStatus,
    HealthStatus,
    RemediationAction,
    RiskLevel,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_action(
    action_type: str = "restart_pod",
    target: str = "pod/web-server-abc123",
    env: Environment = Environment.DEVELOPMENT,
    risk: RiskLevel = RiskLevel.LOW,
    description: str = "Restart unhealthy pod",
    action_id: str = "act-001",
    parameters: dict[str, Any] | None = None,
) -> RemediationAction:
    return RemediationAction(
        id=action_id,
        action_type=action_type,
        target_resource=target,
        environment=env,
        risk_level=risk,
        parameters=parameters or {},
        description=description,
    )


@pytest.fixture()
def toolkit() -> RemediationToolkit:
    """Return a bare toolkit (no connectors/engines)."""
    return RemediationToolkit()


@pytest.fixture()
def mock_router() -> MagicMock:
    return MagicMock()


# ===================================================================
# 1. OPA Approval Workflow — risk-score routing
# ===================================================================


class TestOPAApprovalWorkflow:
    """Test evaluate_risk_score thresholds."""

    def test_auto_approve_below_threshold(self, toolkit: RemediationToolkit) -> None:
        assert toolkit.evaluate_risk_score(0.0) == ApprovalStatus.APPROVED
        assert toolkit.evaluate_risk_score(0.3) == ApprovalStatus.APPROVED
        assert toolkit.evaluate_risk_score(0.49) == ApprovalStatus.APPROVED

    def test_human_approval_in_range(self, toolkit: RemediationToolkit) -> None:
        assert toolkit.evaluate_risk_score(0.5) == ApprovalStatus.PENDING
        assert toolkit.evaluate_risk_score(0.7) == ApprovalStatus.PENDING
        assert toolkit.evaluate_risk_score(0.85) == ApprovalStatus.PENDING

    def test_escalate_above_threshold(self, toolkit: RemediationToolkit) -> None:
        assert toolkit.evaluate_risk_score(0.86) == ApprovalStatus.ESCALATED
        assert toolkit.evaluate_risk_score(0.95) == ApprovalStatus.ESCALATED
        assert toolkit.evaluate_risk_score(1.0) == ApprovalStatus.ESCALATED

    def test_boundary_values(self, toolkit: RemediationToolkit) -> None:
        # Exact boundaries
        assert toolkit.evaluate_risk_score(0.5) == ApprovalStatus.PENDING
        assert toolkit.evaluate_risk_score(0.85) == ApprovalStatus.PENDING
        # Just below auto-approve boundary
        assert toolkit.evaluate_risk_score(0.4999) == ApprovalStatus.APPROVED
        # Just above escalate boundary
        assert toolkit.evaluate_risk_score(0.8501) == ApprovalStatus.ESCALATED


# ===================================================================
# 2. Blast-radius limits per environment
# ===================================================================


class TestBlastRadiusEnforcement:
    """Test enforce_blast_radius and get_blast_radius_limit."""

    def test_limits_constants(self) -> None:
        assert BLAST_RADIUS_LIMITS["development"] == 10
        assert BLAST_RADIUS_LIMITS["staging"] == 5
        assert BLAST_RADIUS_LIMITS["production"] == 3

    def test_within_limit_returns_none(self, toolkit: RemediationToolkit) -> None:
        assert toolkit.enforce_blast_radius("development", 10) is None
        assert toolkit.enforce_blast_radius("staging", 5) is None
        assert toolkit.enforce_blast_radius("production", 3) is None
        assert toolkit.enforce_blast_radius("production", 1) is None

    def test_exceeds_limit_returns_batches(self, toolkit: RemediationToolkit) -> None:
        batches = toolkit.enforce_blast_radius("production", 7)
        assert batches is not None
        # 7 resources / 3 per batch = 3 batches (3, 3, 1)
        assert len(batches) == 3
        assert len(batches[0]) == 3
        assert len(batches[1]) == 3
        assert len(batches[2]) == 1

    def test_exceeds_3x_limit_raises(self, toolkit: RemediationToolkit) -> None:
        # production limit=3, 3x=9, so 10 should raise
        with pytest.raises(BlastRadiusExceeded) as exc_info:
            toolkit.enforce_blast_radius("production", 10)
        assert exc_info.value.environment == "production"
        assert exc_info.value.requested == 10
        assert exc_info.value.limit == 3

    def test_staging_batching(self, toolkit: RemediationToolkit) -> None:
        batches = toolkit.enforce_blast_radius("staging", 12)
        assert batches is not None
        # 12 resources / 5 per batch = 3 batches (5, 5, 2)
        assert len(batches) == 3
        assert len(batches[0]) == 5
        assert len(batches[2]) == 2

    def test_staging_exceeds_3x_raises(self, toolkit: RemediationToolkit) -> None:
        # staging limit=5, 3x=15, so 16 should raise
        with pytest.raises(BlastRadiusExceeded):
            toolkit.enforce_blast_radius("staging", 16)

    def test_unknown_env_uses_production_limit(self, toolkit: RemediationToolkit) -> None:
        assert toolkit.get_blast_radius_limit("unknown") == 3
        assert toolkit.enforce_blast_radius("unknown", 3) is None
        with pytest.raises(BlastRadiusExceeded):
            toolkit.enforce_blast_radius("unknown", 10)

    def test_get_blast_radius_limit(self, toolkit: RemediationToolkit) -> None:
        assert toolkit.get_blast_radius_limit("development") == 10
        assert toolkit.get_blast_radius_limit("staging") == 5
        assert toolkit.get_blast_radius_limit("production") == 3


# ===================================================================
# 3. CrowdStrike containment with mock connector
# ===================================================================


class TestCrowdStrikeContainment:
    """Test contain_host with mocked CrowdStrike connector."""

    @pytest.mark.asyncio()
    async def test_contain_host_success_first_poll(self, mock_router: MagicMock) -> None:
        """Containment succeeds and first poll confirms it."""
        cs_mock = AsyncMock()
        cs_mock.contain_host = AsyncMock(return_value={"status": "ok"})
        cs_mock.get_health = AsyncMock(
            return_value=HealthStatus(
                resource_id="dev-001",
                healthy=True,
                status="contained",
                message="Host contained",
                last_checked=datetime.now(UTC),
            )
        )
        mock_router.get = MagicMock(return_value=cs_mock)

        toolkit = RemediationToolkit(connector_router=mock_router)
        result = await toolkit.contain_host("dev-001", poll_attempts=3, poll_interval_seconds=0.01)

        assert result.status == ExecutionStatus.SUCCESS
        assert "verified" in result.message
        cs_mock.contain_host.assert_awaited_once_with("dev-001")
        cs_mock.get_health.assert_awaited_once()

    @pytest.mark.asyncio()
    async def test_contain_host_verified_on_second_poll(self, mock_router: MagicMock) -> None:
        """Containment verified after second poll attempt."""
        cs_mock = AsyncMock()
        cs_mock.contain_host = AsyncMock(return_value={})
        # First poll: not yet contained. Second poll: contained.
        cs_mock.get_health = AsyncMock(
            side_effect=[
                HealthStatus(
                    resource_id="dev-002",
                    healthy=True,
                    status="normal",
                    last_checked=datetime.now(UTC),
                ),
                HealthStatus(
                    resource_id="dev-002",
                    healthy=True,
                    status="contained",
                    last_checked=datetime.now(UTC),
                ),
            ]
        )
        mock_router.get = MagicMock(return_value=cs_mock)

        toolkit = RemediationToolkit(connector_router=mock_router)
        result = await toolkit.contain_host("dev-002", poll_attempts=3, poll_interval_seconds=0.01)

        assert result.status == ExecutionStatus.SUCCESS
        assert "2 poll" in result.message
        assert cs_mock.get_health.await_count == 2

    @pytest.mark.asyncio()
    async def test_contain_host_no_router(self) -> None:
        """Without a connector router, containment fails gracefully."""
        toolkit = RemediationToolkit()
        result = await toolkit.contain_host("dev-001")

        assert result.status == ExecutionStatus.FAILED
        assert "No connector router" in result.message

    @pytest.mark.asyncio()
    async def test_contain_host_no_crowdstrike_connector(self, mock_router: MagicMock) -> None:
        """CrowdStrike connector not registered."""
        mock_router.get = MagicMock(side_effect=ValueError("Unknown provider: crowdstrike"))

        toolkit = RemediationToolkit(connector_router=mock_router)
        result = await toolkit.contain_host("dev-001")

        assert result.status == ExecutionStatus.FAILED
        assert "not available" in result.message

    @pytest.mark.asyncio()
    async def test_contain_host_api_error(self, mock_router: MagicMock) -> None:
        """CrowdStrike API returns an error during containment."""
        cs_mock = AsyncMock()
        cs_mock.contain_host = AsyncMock(side_effect=RuntimeError("API 500"))
        mock_router.get = MagicMock(return_value=cs_mock)

        toolkit = RemediationToolkit(connector_router=mock_router)
        result = await toolkit.contain_host("dev-001")

        assert result.status == ExecutionStatus.FAILED
        assert "API 500" in result.message

    @pytest.mark.asyncio()
    async def test_contain_host_unverified(self, mock_router: MagicMock) -> None:
        """Containment requested but polls never confirm."""
        cs_mock = AsyncMock()
        cs_mock.contain_host = AsyncMock(return_value={})
        cs_mock.get_health = AsyncMock(
            return_value=HealthStatus(
                resource_id="dev-003",
                healthy=True,
                status="normal",
                last_checked=datetime.now(UTC),
            )
        )
        mock_router.get = MagicMock(return_value=cs_mock)

        toolkit = RemediationToolkit(connector_router=mock_router)
        result = await toolkit.contain_host("dev-003", poll_attempts=2, poll_interval_seconds=0.01)

        assert result.status == ExecutionStatus.SUCCESS
        assert "manual verification" in result.message


# ===================================================================
# 4. ServiceNow ticket creation
# ===================================================================


class TestServiceNowTicketCreation:
    """Test create_servicenow_ticket with mocked ServiceNow connector."""

    @pytest.mark.asyncio()
    async def test_create_ticket_success(self, mock_router: MagicMock) -> None:
        """Ticket created successfully with correct fields."""
        snow_mock = AsyncMock()
        snow_mock.create_incident = AsyncMock(
            return_value={"result": {"number": "INC0012345", "sys_id": "abc"}}
        )
        mock_router.get = MagicMock(return_value=snow_mock)

        toolkit = RemediationToolkit(connector_router=mock_router)
        action = _make_action(
            env=Environment.PRODUCTION,
            risk=RiskLevel.HIGH,
        )

        result = await toolkit.create_servicenow_ticket(
            action=action,
            outcome=ExecutionStatus.SUCCESS,
            rollback_plan="Redeploy previous version",
            alert_id="ALT-999",
            cve_id="CVE-2024-1234",
        )

        assert result["result"]["number"] == "INC0012345"
        snow_mock.create_incident.assert_awaited_once()

        # Verify the call arguments
        call_kwargs = snow_mock.create_incident.call_args.kwargs
        assert "[ShieldOps]" in call_kwargs["short_description"]
        assert "CVE-2024-1234" in call_kwargs["description"]
        assert "ALT-999" in call_kwargs["description"]
        assert "Redeploy previous version" in call_kwargs["description"]
        # Production + HIGH risk -> urgency 1, impact 1
        assert call_kwargs["urgency"] == "1"
        assert call_kwargs["impact"] == "1"

    @pytest.mark.asyncio()
    async def test_create_ticket_staging_medium_risk(self, mock_router: MagicMock) -> None:
        """Staging + MEDIUM risk gets urgency=2, impact=2."""
        snow_mock = AsyncMock()
        snow_mock.create_incident = AsyncMock(return_value={"result": {"number": "INC002"}})
        mock_router.get = MagicMock(return_value=snow_mock)

        toolkit = RemediationToolkit(connector_router=mock_router)
        action = _make_action(env=Environment.STAGING, risk=RiskLevel.MEDIUM)

        await toolkit.create_servicenow_ticket(action=action, outcome=ExecutionStatus.SUCCESS)

        call_kwargs = snow_mock.create_incident.call_args.kwargs
        assert call_kwargs["urgency"] == "2"
        assert call_kwargs["impact"] == "2"

    @pytest.mark.asyncio()
    async def test_create_ticket_no_router(self) -> None:
        """Without router, returns error dict."""
        toolkit = RemediationToolkit()
        action = _make_action()
        result = await toolkit.create_servicenow_ticket(action, ExecutionStatus.SUCCESS)
        assert "error" in result

    @pytest.mark.asyncio()
    async def test_create_ticket_no_servicenow(self, mock_router: MagicMock) -> None:
        """ServiceNow connector not available."""
        mock_router.get = MagicMock(side_effect=ValueError("Unknown provider"))

        toolkit = RemediationToolkit(connector_router=mock_router)
        action = _make_action()
        result = await toolkit.create_servicenow_ticket(action, ExecutionStatus.SUCCESS)
        assert "error" in result

    @pytest.mark.asyncio()
    async def test_create_ticket_api_failure(self, mock_router: MagicMock) -> None:
        """ServiceNow API failure returns error dict."""
        snow_mock = AsyncMock()
        snow_mock.create_incident = AsyncMock(side_effect=RuntimeError("Connection refused"))
        mock_router.get = MagicMock(return_value=snow_mock)

        toolkit = RemediationToolkit(connector_router=mock_router)
        action = _make_action()
        result = await toolkit.create_servicenow_ticket(action, ExecutionStatus.FAILED)
        assert "error" in result
        assert "Connection refused" in result["error"]


# ===================================================================
# 5. Audit trail logging
# ===================================================================


class TestAuditLogging:
    """Test record_audit and get_audit_log."""

    def test_record_audit_basic(self, toolkit: RemediationToolkit) -> None:
        entry = toolkit.record_audit(
            action_type="restart_pod",
            target_resource="pod/web-abc",
            environment="development",
            risk_level=RiskLevel.LOW,
            approval_status=ApprovalStatus.APPROVED,
            outcome=ExecutionStatus.SUCCESS,
            reasoning="Pod was crashlooping",
        )

        assert entry.action == "restart_pod"
        assert entry.target_resource == "pod/web-abc"
        assert entry.environment == Environment.DEVELOPMENT
        assert entry.risk_level == RiskLevel.LOW
        assert entry.approval_status == ApprovalStatus.APPROVED
        assert entry.outcome == ExecutionStatus.SUCCESS
        assert entry.agent_type == "remediation"
        assert entry.reasoning == "Pod was crashlooping"
        assert entry.id.startswith("aud-")

    def test_audit_log_accumulates(self, toolkit: RemediationToolkit) -> None:
        for i in range(3):
            toolkit.record_audit(
                action_type=f"action_{i}",
                target_resource=f"res_{i}",
                environment="staging",
                risk_level=RiskLevel.MEDIUM,
                approval_status=None,
                outcome=ExecutionStatus.SUCCESS,
            )

        log = toolkit.get_audit_log()
        assert len(log) == 3
        assert log[0].action == "action_0"
        assert log[2].action == "action_2"

    def test_audit_log_returns_copy(self, toolkit: RemediationToolkit) -> None:
        toolkit.record_audit(
            action_type="test",
            target_resource="res",
            environment="production",
            risk_level=RiskLevel.HIGH,
            approval_status=ApprovalStatus.PENDING,
            outcome=ExecutionStatus.FAILED,
        )

        log1 = toolkit.get_audit_log()
        log2 = toolkit.get_audit_log()
        assert log1 is not log2  # Returns a copy
        assert len(log1) == len(log2)

    def test_audit_unknown_environment_defaults_to_production(
        self, toolkit: RemediationToolkit
    ) -> None:
        entry = toolkit.record_audit(
            action_type="test",
            target_resource="res",
            environment="unknown_env",
            risk_level=RiskLevel.CRITICAL,
            approval_status=ApprovalStatus.ESCALATED,
            outcome=ExecutionStatus.FAILED,
        )
        assert entry.environment == Environment.PRODUCTION

    def test_audit_with_escalated_status(self, toolkit: RemediationToolkit) -> None:
        entry = toolkit.record_audit(
            action_type="drain_node",
            target_resource="node/worker-1",
            environment="production",
            risk_level=RiskLevel.CRITICAL,
            approval_status=ApprovalStatus.ESCALATED,
            outcome=ExecutionStatus.FAILED,
            policy_evaluation="denied",
            actor="remediation-agent:rem-abc123",
        )

        assert entry.approval_status == ApprovalStatus.ESCALATED
        assert entry.policy_evaluation == "denied"
        assert entry.actor == "remediation-agent:rem-abc123"

    def test_audit_empty_log_initially(self, toolkit: RemediationToolkit) -> None:
        assert toolkit.get_audit_log() == []
