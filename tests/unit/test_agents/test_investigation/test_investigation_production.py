"""Tests for Investigation Agent production-readiness upgrades.

Covers:
- OPA policy checks before infrastructure actions
- LLM fallback heuristics
- Graph compilation and basic execution with mock state
- Persistence calls after execution
- Connector health checks
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.agents.investigation.models import (
    InvestigationState,
    LogFinding,
    MetricAnomaly,
)
from shieldops.agents.investigation.nodes import (
    _heuristic_bottleneck,
    _heuristic_correlate,
    _heuristic_hypotheses,
    _heuristic_resource_pressure,
    correlate_findings,
    generate_hypotheses,
    set_toolkit,
)
from shieldops.agents.investigation.tools import InvestigationToolkit
from shieldops.models.base import AlertContext

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def alert_context() -> AlertContext:
    """Standard alert context for tests."""
    return AlertContext(
        alert_id="alert-test-001",
        alert_name="HighCPUUsage",
        severity="critical",
        source="prometheus",
        resource_id="default/api-server-abc",
        description="CPU usage exceeded 90% for 5 minutes",
        triggered_at=datetime.now(UTC),
        labels={"environment": "production", "service": "api-server", "org_id": "org-1"},
    )


@pytest.fixture()
def investigation_state(alert_context: AlertContext) -> InvestigationState:
    """Populated investigation state for testing downstream nodes."""
    return InvestigationState(
        alert_id=alert_context.alert_id,
        alert_context=alert_context,
        investigation_start=datetime.now(UTC),
        log_findings=[
            LogFinding(
                source="splunk",
                query="default/api-server-abc",
                summary="OOMKilled: container exceeded memory limit",
                severity="error",
                sample_entries=["OOMKilled in container api-server"],
                count=5,
            ),
            LogFinding(
                source="splunk",
                query="default/api-server-abc",
                summary="Connection timeout to downstream db-main",
                severity="error",
                sample_entries=["timeout after 30s connecting to db-main:5432"],
                count=12,
            ),
        ],
        metric_anomalies=[
            MetricAnomaly(
                metric_name="container_cpu_usage_seconds_total",
                source="prometheus",
                current_value=0.95,
                baseline_value=0.30,
                deviation_percent=216.7,
                started_at=datetime.now(UTC),
                labels={"namespace": "default", "pod": "api-server-abc"},
            ),
            MetricAnomaly(
                metric_name="container_memory_usage_bytes",
                source="prometheus",
                current_value=1_800_000_000,
                baseline_value=800_000_000,
                deviation_percent=125.0,
                started_at=datetime.now(UTC),
                labels={"namespace": "default", "pod": "api-server-abc"},
            ),
        ],
    )


@pytest.fixture()
def empty_toolkit() -> InvestigationToolkit:
    """Toolkit with no connectors (safe for unit tests)."""
    return InvestigationToolkit()


# ---------------------------------------------------------------------------
# OPA Policy Check Tests
# ---------------------------------------------------------------------------


class TestOPAPolicyChecks:
    """Verify OPA policy is called before infrastructure actions."""

    @pytest.mark.asyncio()
    async def test_query_logs_calls_policy(self, empty_toolkit: InvestigationToolkit) -> None:
        """query_logs should evaluate policy before querying infrastructure."""
        with patch(
            "shieldops.agents.investigation.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_evaluate:
            # Set up policy to deny
            mock_decision = MagicMock()
            mock_decision.allowed = False
            mock_decision.decision.value = "denied"
            mock_decision.reason = "Test deny"
            mock_evaluate.return_value = mock_decision

            result = await empty_toolkit.query_logs(resource_id="default/test-pod")

            mock_evaluate.assert_called_once()
            call_kwargs = mock_evaluate.call_args
            assert call_kwargs[1]["action"] == "query_logs"
            assert result["policy_denied"] is True
            assert result["total_entries"] == 0

    @pytest.mark.asyncio()
    async def test_query_metrics_calls_policy(self, empty_toolkit: InvestigationToolkit) -> None:
        """query_metrics should evaluate policy before querying infrastructure."""
        with patch(
            "shieldops.agents.investigation.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_evaluate:
            mock_decision = MagicMock()
            mock_decision.allowed = False
            mock_decision.decision.value = "denied"
            mock_decision.reason = "Test deny"
            mock_evaluate.return_value = mock_decision

            result = await empty_toolkit.query_metrics(resource_id="default/test-pod")

            mock_evaluate.assert_called_once()
            assert result["policy_denied"] is True
            assert result["anomaly_count"] == 0

    @pytest.mark.asyncio()
    async def test_query_traces_calls_policy(self, empty_toolkit: InvestigationToolkit) -> None:
        """query_traces should evaluate policy before querying infrastructure."""
        with patch(
            "shieldops.agents.investigation.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_evaluate:
            mock_decision = MagicMock()
            mock_decision.allowed = False
            mock_decision.decision.value = "denied"
            mock_decision.reason = "Test deny"
            mock_evaluate.return_value = mock_decision

            result = await empty_toolkit.query_traces(service_name="api-server")

            mock_evaluate.assert_called_once()
            assert result["policy_denied"] is True
            assert result["traces"] == []

    @pytest.mark.asyncio()
    async def test_policy_allowed_proceeds(self, empty_toolkit: InvestigationToolkit) -> None:
        """When policy allows, the action should proceed normally."""
        with patch(
            "shieldops.agents.investigation.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_evaluate:
            mock_decision = MagicMock()
            mock_decision.allowed = True
            mock_decision.decision.value = "approved"
            mock_decision.reason = "Auto-approved"
            mock_evaluate.return_value = mock_decision

            # No connectors, so result will be empty but should NOT have policy_denied
            result = await empty_toolkit.query_logs(resource_id="default/test-pod")

            mock_evaluate.assert_called_once()
            assert "policy_denied" not in result
            assert result["total_entries"] == 0  # No connectors, but action allowed

    @pytest.mark.asyncio()
    async def test_policy_error_fails_open(self, empty_toolkit: InvestigationToolkit) -> None:
        """On policy evaluation error, fail-open for read-only actions."""
        with patch(
            "shieldops.agents.investigation.tools.policy_evaluate",
            new_callable=AsyncMock,
            side_effect=Exception("OPA unreachable"),
        ):
            # Should not raise; should proceed with action
            result = await empty_toolkit.query_logs(resource_id="default/test-pod")
            assert "policy_denied" not in result

    @pytest.mark.asyncio()
    async def test_get_k8s_events_calls_policy(self, empty_toolkit: InvestigationToolkit) -> None:
        """get_k8s_events should evaluate policy before querying K8s."""
        with patch(
            "shieldops.agents.investigation.tools.policy_evaluate",
            new_callable=AsyncMock,
        ) as mock_evaluate:
            mock_decision = MagicMock()
            mock_decision.allowed = False
            mock_decision.decision.value = "denied"
            mock_decision.reason = "Test deny"
            mock_evaluate.return_value = mock_decision

            result = await empty_toolkit.get_k8s_events(resource_id="default/test-pod")

            mock_evaluate.assert_called_once()
            assert result == []


# ---------------------------------------------------------------------------
# LLM Fallback Tests
# ---------------------------------------------------------------------------


class TestLLMFallback:
    """Verify heuristic fallback produces reasonable output when LLM is unavailable."""

    def test_heuristic_resource_pressure_critical(self) -> None:
        """High deviation should classify as critical pressure."""
        anomalies = [
            MetricAnomaly(
                metric_name="cpu",
                source="prom",
                current_value=0.95,
                baseline_value=0.3,
                deviation_percent=216.0,
                started_at=datetime.now(UTC),
            ),
        ]
        assert _heuristic_resource_pressure(anomalies) == "critical"

    def test_heuristic_resource_pressure_none(self) -> None:
        """No anomalies should classify as none."""
        assert _heuristic_resource_pressure([]) == "none"

    def test_heuristic_resource_pressure_moderate(self) -> None:
        """Two anomalies with moderate deviation should classify as moderate."""
        anomalies = [
            MetricAnomaly(
                metric_name="cpu",
                source="prom",
                current_value=0.6,
                baseline_value=0.3,
                deviation_percent=60.0,
                started_at=datetime.now(UTC),
            ),
            MetricAnomaly(
                metric_name="mem",
                source="prom",
                current_value=900,
                baseline_value=500,
                deviation_percent=80.0,
                started_at=datetime.now(UTC),
            ),
        ]
        assert _heuristic_resource_pressure(anomalies) == "moderate"

    def test_heuristic_bottleneck_cpu(self) -> None:
        """CPU metric anomaly should identify CPU bottleneck."""
        anomalies = [
            MetricAnomaly(
                metric_name="container_cpu_usage_seconds_total",
                source="prom",
                current_value=0.95,
                baseline_value=0.3,
                deviation_percent=216.0,
                started_at=datetime.now(UTC),
            ),
        ]
        assert _heuristic_bottleneck(anomalies) == "cpu"

    def test_heuristic_bottleneck_memory(self) -> None:
        """Memory metric anomaly should identify memory bottleneck."""
        anomalies = [
            MetricAnomaly(
                metric_name="container_memory_usage_bytes",
                source="prom",
                current_value=1800,
                baseline_value=800,
                deviation_percent=125.0,
                started_at=datetime.now(UTC),
            ),
        ]
        assert _heuristic_bottleneck(anomalies) == "memory"

    def test_heuristic_correlate_produces_events(
        self,
        investigation_state: InvestigationState,
    ) -> None:
        """Heuristic correlation should pair error logs with metric anomalies."""
        correlated = _heuristic_correlate(investigation_state)
        assert len(correlated) > 0
        assert all(c.source == "heuristic-correlation" for c in correlated)
        assert all(0.0 <= c.correlation_score <= 1.0 for c in correlated)

    def test_heuristic_hypotheses_oom(self, investigation_state: InvestigationState) -> None:
        """Keyword-based hypothesis should detect OOM from log findings."""
        hypotheses, confidence = _heuristic_hypotheses(investigation_state)
        assert len(hypotheses) > 0
        oom_hyp = [h for h in hypotheses if "memory" in h.description.lower()]
        assert len(oom_hyp) > 0
        assert confidence > 0.0

    def test_heuristic_hypotheses_timeout(self, investigation_state: InvestigationState) -> None:
        """Keyword-based hypothesis should detect timeout from log findings."""
        hypotheses, _ = _heuristic_hypotheses(investigation_state)
        timeout_hyp = [
            h
            for h in hypotheses
            if "timeout" in h.description.lower() or "connectivity" in h.description.lower()
        ]
        assert len(timeout_hyp) > 0

    def test_heuristic_hypotheses_default_fallback(self) -> None:
        """With no keyword matches, should produce a default hypothesis."""
        state = InvestigationState(
            alert_id="test",
            alert_context=AlertContext(
                alert_id="test",
                alert_name="UnknownAlert",
                severity="warning",
                source="test",
                triggered_at=datetime.now(UTC),
                labels={},
            ),
        )
        hypotheses, confidence = _heuristic_hypotheses(state)
        assert len(hypotheses) == 1
        assert confidence == 0.3  # Default low confidence

    @pytest.mark.asyncio()
    async def test_generate_hypotheses_falls_back_on_llm_error(
        self,
        investigation_state: InvestigationState,
        empty_toolkit: InvestigationToolkit,
    ) -> None:
        """generate_hypotheses should use heuristic fallback when LLM fails."""
        set_toolkit(empty_toolkit)

        with patch(
            "shieldops.agents.investigation.nodes.llm_structured",
            new_callable=AsyncMock,
            side_effect=Exception("LLM unavailable"),
        ):
            result = await generate_hypotheses(investigation_state)

        assert "hypotheses" in result
        assert len(result["hypotheses"]) > 0
        assert "LLM unavailable" in result["reasoning_chain"][-1].output_summary

    @pytest.mark.asyncio()
    async def test_correlate_findings_falls_back_on_llm_error(
        self,
        investigation_state: InvestigationState,
        empty_toolkit: InvestigationToolkit,
    ) -> None:
        """correlate_findings should use heuristic fallback when LLM fails."""
        set_toolkit(empty_toolkit)

        with patch(
            "shieldops.agents.investigation.nodes.llm_structured",
            new_callable=AsyncMock,
            side_effect=Exception("LLM unavailable"),
        ):
            result = await correlate_findings(investigation_state)

        assert "correlated_events" in result
        assert len(result["correlated_events"]) > 0
        assert "Heuristic correlation" in result["reasoning_chain"][-1].output_summary


# ---------------------------------------------------------------------------
# Graph Compilation Tests
# ---------------------------------------------------------------------------


class TestGraphCompilation:
    """Verify the investigation graph compiles and executes with mock state."""

    def test_graph_compiles(self) -> None:
        """create_investigation_graph() should compile without errors."""
        from shieldops.agents.investigation.graph import create_investigation_graph

        graph = create_investigation_graph()
        app = graph.compile()
        assert app is not None

    def test_graph_has_expected_nodes(self) -> None:
        """Graph should have all expected node names."""
        from shieldops.agents.investigation.graph import create_investigation_graph

        graph = create_investigation_graph()
        expected_nodes = {
            "gather_context",
            "check_historical_patterns",
            "analyze_logs",
            "analyze_metrics",
            "analyze_traces",
            "correlate_findings",
            "generate_hypotheses",
            "recommend_action",
        }
        assert expected_nodes.issubset(set(graph.nodes.keys()))


# ---------------------------------------------------------------------------
# Persistence Tests
# ---------------------------------------------------------------------------


class TestPersistence:
    """Verify persistence is called after graph execution."""

    @pytest.mark.asyncio()
    async def test_persist_agent_run_called_on_success(
        self,
        alert_context: AlertContext,
    ) -> None:
        """persist_agent_run and write_audit_log should be called after successful run."""
        with (
            patch(
                "shieldops.agents.investigation.runner.persist_agent_run",
                new_callable=AsyncMock,
            ) as mock_persist,
            patch(
                "shieldops.agents.investigation.runner.write_audit_log",
                new_callable=AsyncMock,
            ) as mock_audit,
            patch(
                "shieldops.agents.investigation.runner.check_agent_connectors",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "shieldops.agents.investigation.runner.get_tracer",
            ) as mock_tracer,
        ):
            # Mock the tracer context manager
            mock_span = MagicMock()
            mock_span.set_attribute = MagicMock()
            mock_tracer.return_value.start_as_current_span.return_value.__enter__ = lambda _: (
                mock_span
            )
            mock_tracer.return_value.start_as_current_span.return_value.__exit__ = lambda *_: None

            from shieldops.agents.investigation.runner import InvestigationRunner

            runner = InvestigationRunner()

            # Mock the compiled graph's ainvoke
            mock_final_state = InvestigationState(
                alert_id=alert_context.alert_id,
                alert_context=alert_context,
                investigation_start=datetime.now(UTC),
                current_step="complete",
                confidence_score=0.7,
            )
            runner._app = AsyncMock()
            runner._app.ainvoke = AsyncMock(return_value=mock_final_state.model_dump())

            await runner.investigate(alert_context)

            mock_persist.assert_called_once()
            persist_kwargs = mock_persist.call_args[1]
            assert persist_kwargs["agent_name"] == "investigation"
            assert persist_kwargs["org_id"] == "org-1"

            mock_audit.assert_called_once()
            audit_kwargs = mock_audit.call_args[1]
            assert audit_kwargs["action"] == "investigation.completed"
            assert audit_kwargs["actor"] == "investigation-agent"

    @pytest.mark.asyncio()
    async def test_persist_agent_run_called_on_failure(
        self,
        alert_context: AlertContext,
    ) -> None:
        """persist_agent_run should be called with error on failed investigation."""
        with (
            patch(
                "shieldops.agents.investigation.runner.persist_agent_run",
                new_callable=AsyncMock,
            ) as mock_persist,
            patch(
                "shieldops.agents.investigation.runner.write_audit_log",
                new_callable=AsyncMock,
            ) as mock_audit,
            patch(
                "shieldops.agents.investigation.runner.check_agent_connectors",
                new_callable=AsyncMock,
                return_value={},
            ),
            patch(
                "shieldops.agents.investigation.runner.get_tracer",
            ) as mock_tracer,
        ):
            mock_span = MagicMock()
            mock_span.set_attribute = MagicMock()
            mock_tracer.return_value.start_as_current_span.return_value.__enter__ = lambda _: (
                mock_span
            )
            mock_tracer.return_value.start_as_current_span.return_value.__exit__ = lambda *_: None

            from shieldops.agents.investigation.runner import InvestigationRunner

            runner = InvestigationRunner()
            runner._app = AsyncMock()
            runner._app.ainvoke = AsyncMock(side_effect=RuntimeError("Graph execution failed"))

            result = await runner.investigate(alert_context)

            assert result.error == "Graph execution failed"
            mock_persist.assert_called_once()
            persist_kwargs = mock_persist.call_args[1]
            assert persist_kwargs["error_message"] == "Graph execution failed"

            mock_audit.assert_called_once()
            audit_kwargs = mock_audit.call_args[1]
            assert audit_kwargs["action"] == "investigation.failed"


# ---------------------------------------------------------------------------
# Connector Health Check Tests
# ---------------------------------------------------------------------------


class TestConnectorHealthCheck:
    """Verify connector health checks run before investigation."""

    @pytest.mark.asyncio()
    async def test_health_check_called_before_execution(
        self,
        alert_context: AlertContext,
    ) -> None:
        """check_agent_connectors should be called during investigate()."""
        with (
            patch(
                "shieldops.agents.investigation.runner.check_agent_connectors",
                new_callable=AsyncMock,
                return_value={},
            ) as mock_health,
            patch(
                "shieldops.agents.investigation.runner.persist_agent_run",
                new_callable=AsyncMock,
            ),
            patch(
                "shieldops.agents.investigation.runner.write_audit_log",
                new_callable=AsyncMock,
            ),
            patch(
                "shieldops.agents.investigation.runner.get_tracer",
            ) as mock_tracer,
        ):
            mock_span = MagicMock()
            mock_span.set_attribute = MagicMock()
            mock_tracer.return_value.start_as_current_span.return_value.__enter__ = lambda _: (
                mock_span
            )
            mock_tracer.return_value.start_as_current_span.return_value.__exit__ = lambda *_: None

            from shieldops.agents.investigation.runner import InvestigationRunner

            runner = InvestigationRunner()
            mock_final_state = InvestigationState(
                alert_id=alert_context.alert_id,
                alert_context=alert_context,
                investigation_start=datetime.now(UTC),
                current_step="complete",
            )
            runner._app = AsyncMock()
            runner._app.ainvoke = AsyncMock(return_value=mock_final_state.model_dump())

            await runner.investigate(alert_context)

            mock_health.assert_called_once()
            call_kwargs = mock_health.call_args[1]
            assert call_kwargs["agent_name"] == "investigation"
            assert "kubernetes" in call_kwargs["required_connectors"]
            assert "splunk" in call_kwargs["required_connectors"]
            assert "crowdstrike" in call_kwargs["required_connectors"]
