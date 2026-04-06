"""Production-readiness tests for the Remediation Agent.

Tests cover:
1. OPA policy gate called before infrastructure-modifying actions
2. Blast-radius enforcement aborts when limit exceeded
3. LLM fallback heuristics when llm_structured fails
4. Persistence helpers called after execution
5. Graph compiles successfully
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.agents.remediation.graph import create_remediation_graph
from shieldops.agents.remediation.models import RemediationState
from shieldops.agents.remediation.nodes import (
    assess_risk,
    execute_action,
    set_toolkit,
    validate_health,
)
from shieldops.agents.remediation.tools import (
    RemediationToolkit,
)
from shieldops.models.base import (
    ActionResult,
    Environment,
    ExecutionStatus,
    HealthStatus,
    RemediationAction,
    RiskLevel,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_action() -> RemediationAction:
    return RemediationAction(
        id="act-001",
        action_type="restart_pod",
        target_resource="pod/web-server-abc123",
        environment=Environment.PRODUCTION,
        risk_level=RiskLevel.MEDIUM,
        parameters={"namespace": "default"},
        description="Restart crashing pod",
    )


@pytest.fixture
def sample_action_destructive() -> RemediationAction:
    return RemediationAction(
        id="act-002",
        action_type="terminate_instance",
        target_resource="i-0abc123",
        environment=Environment.PRODUCTION,
        risk_level=RiskLevel.HIGH,
        parameters={},
        description="Terminate compromised instance",
    )


@pytest.fixture
def sample_state(sample_action: RemediationAction) -> RemediationState:
    return RemediationState(
        remediation_id="rem-test001",
        action=sample_action,
    )


@pytest.fixture
def sample_state_destructive(
    sample_action_destructive: RemediationAction,
) -> RemediationState:
    return RemediationState(
        remediation_id="rem-test002",
        action=sample_action_destructive,
    )


# ---------------------------------------------------------------------------
# 1. OPA policy gate called before modify actions
# ---------------------------------------------------------------------------


class TestOPAPolicyGate:
    """Verify the policy gate is evaluated for infrastructure-modifying actions."""

    @pytest.mark.asyncio
    async def test_evaluate_policy_gate_calls_policy_engine(
        self, sample_action: RemediationAction
    ) -> None:
        """evaluate_policy_gate() invokes the three-tier policy engine."""
        mock_decision = MagicMock()
        mock_decision.allowed = True
        mock_decision.decision.value = "approved"
        mock_decision.reason = "Auto-approved: risk score below threshold."

        with patch(
            "shieldops.policy.engine.evaluate",
            new_callable=AsyncMock,
            return_value=mock_decision,
        ) as mock_evaluate:
            toolkit = RemediationToolkit()
            result = await toolkit.evaluate_policy_gate(sample_action)

            mock_evaluate.assert_called_once()
            call_args = mock_evaluate.call_args
            # First positional arg is the action type
            assert call_args[0][0] == "restart_pod"
            # Second positional arg is the PolicyContext
            ctx = call_args[0][1]
            assert ctx.agent_name == "remediation-agent"
            assert ctx.action_type == "restart_pod"
            assert result.allowed is True

    @pytest.mark.asyncio
    async def test_evaluate_policy_gate_denied(
        self, sample_action_destructive: RemediationAction
    ) -> None:
        """Policy engine denial is correctly propagated."""
        from shieldops.policy.engine import Decision

        mock_decision = MagicMock()
        mock_decision.allowed = False
        mock_decision.decision = Decision.DENIED
        mock_decision.reason = "Risk score too high."

        with patch(
            "shieldops.policy.engine.evaluate",
            new_callable=AsyncMock,
            return_value=mock_decision,
        ):
            toolkit = RemediationToolkit()
            result = await toolkit.evaluate_policy_gate(sample_action_destructive)

            assert result.allowed is False
            assert result.decision == "denied"

    @pytest.mark.asyncio
    async def test_evaluate_policy_gate_requires_approval(
        self, sample_action: RemediationAction
    ) -> None:
        """Actions requiring approval return requires_approval=True."""
        from shieldops.policy.engine import Decision

        mock_decision = MagicMock()
        mock_decision.allowed = False
        mock_decision.decision = Decision.REQUIRES_APPROVAL
        mock_decision.reason = "Risk score requires human approval."

        with patch(
            "shieldops.policy.engine.evaluate",
            new_callable=AsyncMock,
            return_value=mock_decision,
        ):
            toolkit = RemediationToolkit()
            result = await toolkit.evaluate_policy_gate(sample_action)

            assert result.requires_approval is True
            assert result.allowed is False


# ---------------------------------------------------------------------------
# 2. Blast-radius enforcement
# ---------------------------------------------------------------------------


class TestBlastRadiusEnforcement:
    """Verify blast-radius limits abort execution when exceeded."""

    @pytest.mark.asyncio
    async def test_blast_radius_within_limits(self, sample_action: RemediationAction) -> None:
        """Single resource in prod is within the limit of 3."""
        from shieldops.policy.blast_radius import check_blast_radius

        result = check_blast_radius(
            environment="prod",
            target_resources=[sample_action.target_resource],
        )
        assert result.allowed is True
        assert result.resource_count == 1

    @pytest.mark.asyncio
    async def test_blast_radius_exceeded_in_prod(self) -> None:
        """4 resources in prod exceeds the limit of 3."""
        from shieldops.policy.blast_radius import check_blast_radius

        result = check_blast_radius(
            environment="prod",
            target_resources=["r1", "r2", "r3", "r4"],
        )
        assert result.allowed is False
        assert result.resource_count == 4
        assert result.limit == 3

    @pytest.mark.asyncio
    async def test_runner_aborts_on_blast_radius(self, sample_action: RemediationAction) -> None:
        """RemediationRunner.remediate() returns error when blast radius exceeded."""
        sample_action.parameters["additional_resources"] = [
            "r2",
            "r3",
            "r4",
        ]

        with patch("shieldops.agents.remediation.runner.check_blast_radius") as mock_br:
            mock_br.return_value = MagicMock(
                allowed=False,
                resource_count=4,
                limit=3,
                reason="Blast-radius exceeded: 4 resources, limit 3.",
            )

            # We need to patch the graph compilation to avoid import issues
            with (
                patch("shieldops.agents.remediation.runner.create_remediation_graph"),
                patch("shieldops.agents.remediation.runner.RollbackManager"),
            ):
                from shieldops.agents.remediation.runner import (
                    RemediationRunner,
                )

                runner = RemediationRunner.__new__(RemediationRunner)
                runner._toolkit = RemediationToolkit()
                runner._remediations = {}
                runner._repository = None
                runner._ws_manager = None
                runner._app = MagicMock()

                result = await runner.remediate(sample_action)

                assert result.current_step == "blast_radius_exceeded"
                assert "Blast-radius exceeded" in result.error


# ---------------------------------------------------------------------------
# 3. LLM fallback heuristics
# ---------------------------------------------------------------------------


class TestLLMFallback:
    """Verify rule-based fallback when llm_structured() fails."""

    @pytest.mark.asyncio
    async def test_assess_risk_fallback_destructive_action(
        self, sample_state_destructive: RemediationState
    ) -> None:
        """Destructive actions escalate to CRITICAL when LLM fails."""
        mock_toolkit = MagicMock()
        mock_toolkit.classify_risk.return_value = RiskLevel.MEDIUM
        set_toolkit(mock_toolkit)

        with patch(
            "shieldops.agents.remediation.nodes.llm_structured",
            new_callable=AsyncMock,
            side_effect=RuntimeError("LLM unavailable"),
        ):
            result = await assess_risk(sample_state_destructive)

        assert result["assessed_risk"] == RiskLevel.CRITICAL
        assert "fallback-heuristic" in result["reasoning_chain"][-1].output_summary

    @pytest.mark.asyncio
    async def test_assess_risk_fallback_prod_action(self, sample_state: RemediationState) -> None:
        """Production non-destructive actions escalate to HIGH when LLM fails."""
        mock_toolkit = MagicMock()
        mock_toolkit.classify_risk.return_value = RiskLevel.LOW
        set_toolkit(mock_toolkit)

        with patch(
            "shieldops.agents.remediation.nodes.llm_structured",
            new_callable=AsyncMock,
            side_effect=RuntimeError("LLM unavailable"),
        ):
            result = await assess_risk(sample_state)

        assert result["assessed_risk"] == RiskLevel.HIGH
        assert "fallback-heuristic" in result["reasoning_chain"][-1].output_summary

    @pytest.mark.asyncio
    async def test_validate_health_fallback(self, sample_state: RemediationState) -> None:
        """validate_health uses raw check results when LLM fails."""

        mock_toolkit = MagicMock()
        mock_health = HealthStatus(
            resource_id="pod/web-server-abc123",
            healthy=True,
            status="running",
            message="OK",
            last_checked=datetime.now(UTC),
        )
        mock_toolkit.validate_health = AsyncMock(return_value=mock_health)
        set_toolkit(mock_toolkit)

        # Set execution_result so the LLM path is attempted
        sample_state.execution_result = ActionResult(
            action_id="act-001",
            status=ExecutionStatus.SUCCESS,
            message="Pod restarted",
            started_at=datetime.now(UTC),
        )

        with patch(
            "shieldops.agents.remediation.nodes.llm_structured",
            new_callable=AsyncMock,
            side_effect=RuntimeError("LLM unavailable"),
        ):
            result = await validate_health(sample_state)

        # Should still produce a valid result using raw checks
        assert result["validation_passed"] is True
        assert "LLM fallback" in result["reasoning_chain"][-1].output_summary


# ---------------------------------------------------------------------------
# 4. Persistence called after execution
# ---------------------------------------------------------------------------


class TestPersistence:
    """Verify persist_agent_run and write_audit_log are called."""

    @pytest.mark.asyncio
    async def test_persist_agent_run_called_on_success(
        self, sample_action: RemediationAction
    ) -> None:
        """persist_agent_run() is invoked after successful remediation."""
        with (
            patch(
                "shieldops.agents.remediation.runner.persist_agent_run",
                new_callable=AsyncMock,
            ) as mock_persist,
            patch(
                "shieldops.agents.remediation.runner.write_audit_log",
                new_callable=AsyncMock,
            ) as mock_audit,
            patch("shieldops.agents.remediation.runner.check_blast_radius") as mock_br,
            patch("shieldops.agents.remediation.runner.create_remediation_graph"),
            patch("shieldops.agents.remediation.runner.RollbackManager"),
        ):
            mock_br.return_value = MagicMock(allowed=True, resource_count=1, limit=3)

            from shieldops.agents.remediation.runner import RemediationRunner

            runner = RemediationRunner.__new__(RemediationRunner)
            runner._toolkit = RemediationToolkit()
            runner._remediations = {}
            runner._repository = None
            runner._ws_manager = None

            # Mock the compiled app to return a valid state dict
            mock_app = AsyncMock()
            mock_app.ainvoke.return_value = RemediationState(
                remediation_id="rem-test",
                action=sample_action,
                current_step="validate_health",
                validation_passed=True,
                remediation_start=datetime.now(UTC),
            ).model_dump()
            runner._app = mock_app

            with patch("shieldops.agents.remediation.runner.get_tracer") as mock_tracer:
                mock_span = MagicMock()
                mock_span.__enter__ = MagicMock(return_value=mock_span)
                mock_span.__exit__ = MagicMock(return_value=False)
                mock_tracer.return_value.start_as_current_span.return_value = mock_span

                await runner.remediate(sample_action)

            mock_persist.assert_called_once()
            assert mock_persist.call_args[1]["agent_name"] == "remediation"
            mock_audit.assert_called_once()
            assert mock_audit.call_args[1]["actor"].startswith("remediation-agent:")

    @pytest.mark.asyncio
    async def test_persist_agent_run_called_on_error(
        self, sample_action: RemediationAction
    ) -> None:
        """persist_agent_run() is invoked even when remediation fails."""
        with (
            patch(
                "shieldops.agents.remediation.runner.persist_agent_run",
                new_callable=AsyncMock,
            ) as mock_persist,
            patch(
                "shieldops.agents.remediation.runner.write_audit_log",
                new_callable=AsyncMock,
            ),
            patch("shieldops.agents.remediation.runner.check_blast_radius") as mock_br,
            patch("shieldops.agents.remediation.runner.create_remediation_graph"),
            patch("shieldops.agents.remediation.runner.RollbackManager"),
        ):
            mock_br.return_value = MagicMock(allowed=True, resource_count=1, limit=3)

            from shieldops.agents.remediation.runner import RemediationRunner

            runner = RemediationRunner.__new__(RemediationRunner)
            runner._toolkit = RemediationToolkit()
            runner._remediations = {}
            runner._repository = None
            runner._ws_manager = None

            # Mock the compiled app to raise an exception
            mock_app = AsyncMock()
            mock_app.ainvoke.side_effect = RuntimeError("Graph execution failed")
            runner._app = mock_app

            with patch("shieldops.agents.remediation.runner.get_tracer") as mock_tracer:
                mock_span = MagicMock()
                mock_span.__enter__ = MagicMock(return_value=mock_span)
                mock_span.__exit__ = MagicMock(return_value=False)
                mock_tracer.return_value.start_as_current_span.return_value = mock_span

                result = await runner.remediate(sample_action)

            assert result.error == "Graph execution failed"
            mock_persist.assert_called_once()


# ---------------------------------------------------------------------------
# 5. Graph compiles
# ---------------------------------------------------------------------------


class TestGraphCompiles:
    """Verify the LangGraph workflow compiles without errors."""

    def test_create_remediation_graph_compiles(self) -> None:
        """create_remediation_graph() returns a compilable StateGraph."""
        graph = create_remediation_graph()
        compiled = graph.compile()
        assert compiled is not None

    def test_graph_has_expected_nodes(self) -> None:
        """Graph contains all required workflow nodes."""
        graph = create_remediation_graph()
        node_names = set(graph.nodes.keys())
        expected = {
            "evaluate_policy",
            "resolve_playbook",
            "assess_risk",
            "request_approval",
            "create_snapshot",
            "execute_action",
            "validate_health",
            "perform_rollback",
        }
        assert expected.issubset(node_names)


# ---------------------------------------------------------------------------
# Pre/post verification
# ---------------------------------------------------------------------------


class TestPrePostVerification:
    """Verify pre/post state checks around execute_action."""

    @pytest.mark.asyncio
    async def test_pre_check_captures_state(self) -> None:
        """pre_check_state returns health status from connector."""
        mock_router = MagicMock()
        mock_connector = AsyncMock()
        expected_health = HealthStatus(
            resource_id="pod/test",
            healthy=True,
            status="running",
            message="OK",
            last_checked=datetime.now(UTC),
        )
        mock_connector.get_health.return_value = expected_health
        mock_router.get.return_value = mock_connector

        toolkit = RemediationToolkit(connector_router=mock_router)
        result = await toolkit.pre_check_state("pod/test")

        assert result is not None
        assert result.status == "running"

    @pytest.mark.asyncio
    async def test_post_check_detects_state_change(self) -> None:
        """post_check_state reports True when status changed."""
        mock_router = MagicMock()
        mock_connector = AsyncMock()
        post_health = HealthStatus(
            resource_id="pod/test",
            healthy=True,
            status="running",
            message="OK",
            last_checked=datetime.now(UTC),
        )
        mock_connector.get_health.return_value = post_health
        mock_router.get.return_value = mock_connector

        pre_health = HealthStatus(
            resource_id="pod/test",
            healthy=False,
            status="crash_looping",
            message="CrashLoopBackOff",
            last_checked=datetime.now(UTC),
        )

        toolkit = RemediationToolkit(connector_router=mock_router)
        result_health, changed = await toolkit.post_check_state("pod/test", pre_health)

        assert changed is True
        assert result_health is not None
        assert result_health.status == "running"

    @pytest.mark.asyncio
    async def test_post_check_warns_on_no_change(self) -> None:
        """post_check_state returns False when status unchanged."""
        mock_router = MagicMock()
        mock_connector = AsyncMock()
        same_health = HealthStatus(
            resource_id="pod/test",
            healthy=False,
            status="crash_looping",
            message="Still crashing",
            last_checked=datetime.now(UTC),
        )
        mock_connector.get_health.return_value = same_health
        mock_router.get.return_value = mock_connector

        pre_health = HealthStatus(
            resource_id="pod/test",
            healthy=False,
            status="crash_looping",
            message="CrashLoopBackOff",
            last_checked=datetime.now(UTC),
        )

        toolkit = RemediationToolkit(connector_router=mock_router)
        _, changed = await toolkit.post_check_state("pod/test", pre_health)

        assert changed is False

    @pytest.mark.asyncio
    async def test_execute_action_node_includes_verification(
        self, sample_state: RemediationState
    ) -> None:
        """execute_action node calls pre_check_state and post_check_state."""
        mock_toolkit = MagicMock()
        pre_health = HealthStatus(
            resource_id="pod/web-server-abc123",
            healthy=False,
            status="crash_looping",
            message="",
            last_checked=datetime.now(UTC),
        )
        post_health = HealthStatus(
            resource_id="pod/web-server-abc123",
            healthy=True,
            status="running",
            message="",
            last_checked=datetime.now(UTC),
        )
        mock_toolkit.pre_check_state = AsyncMock(return_value=pre_health)
        mock_toolkit.post_check_state = AsyncMock(return_value=(post_health, True))
        mock_toolkit.execute_action = AsyncMock(
            return_value=ActionResult(
                action_id="act-001",
                status=ExecutionStatus.SUCCESS,
                message="Pod restarted",
                started_at=datetime.now(UTC),
            )
        )
        set_toolkit(mock_toolkit)

        result = await execute_action(sample_state)

        mock_toolkit.pre_check_state.assert_called_once()
        mock_toolkit.post_check_state.assert_called_once()
        assert result["execution_result"].status == ExecutionStatus.SUCCESS
