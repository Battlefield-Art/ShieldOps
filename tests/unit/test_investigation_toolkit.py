"""Tests for Investigation Agent production hardening.

Covers:
- Toolkit audit logging on every method
- Graceful fallback when connectors are unavailable
- LLM root cause analysis with fallback
- CrowdStrike detection context retrieval
- OPA policy integration in the runner
- Audit trail persistence after investigations
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shieldops.agents.investigation.models import InvestigationState
from shieldops.agents.investigation.tools import InvestigationToolkit
from shieldops.models.base import AlertContext

# --- Fixtures ---


@pytest.fixture
def alert_context():
    return AlertContext(
        alert_id="alert-test-001",
        alert_name="KubePodCrashLooping",
        severity="critical",
        source="prometheus",
        resource_id="default/api-server",
        labels={"app": "api", "environment": "production"},
        triggered_at=datetime.now(UTC),
        description="Pod api-server has restarted 15 times in the last hour",
    )


@pytest.fixture
def mock_log_source():
    source = AsyncMock()
    source.source_name = "kubernetes"
    source.query_logs = AsyncMock(
        return_value=[
            {"timestamp": "2025-01-01T00:00:00Z", "message": "ERROR OOMKilled", "level": "error"},
            {"timestamp": "2025-01-01T00:00:01Z", "message": "INFO Starting", "level": "info"},
        ]
    )
    source.search_patterns = AsyncMock(
        return_value={
            "error": [{"message": "ERROR OOMKilled"}],
            "OOMKilled": [{"message": "ERROR OOMKilled"}],
        }
    )
    return source


@pytest.fixture
def mock_metric_source():
    source = AsyncMock()
    source.source_name = "prometheus"
    source.query_instant = AsyncMock(return_value=[{"value": 1073741824}])
    source.detect_anomalies = AsyncMock(
        return_value=[
            {
                "metric_name": "container_memory_usage_bytes",
                "current_value": 1073741824,
                "baseline_value": 536870912,
                "deviation_percent": 100.0,
                "labels": {"namespace": "default", "pod": "api-server"},
            },
        ]
    )
    return source


@pytest.fixture
def mock_connector_router():
    router = MagicMock()
    connector = AsyncMock()
    connector.get_events = AsyncMock(
        return_value=[
            {"reason": "OOMKilling", "message": "Memory cgroup out of memory"},
        ]
    )
    connector.get_health = AsyncMock(
        return_value=MagicMock(
            model_dump=lambda: {
                "healthy": False,
                "status": "CrashLoopBackOff",
                "message": "Restarting",
            }
        )
    )
    router.get = MagicMock(return_value=connector)
    return router


# ============================================================================
# Toolkit audit logging tests
# ============================================================================


class TestToolkitAuditLogging:
    """Verify that every toolkit method emits structured audit logs."""

    @pytest.mark.asyncio
    async def test_query_logs_emits_audit_log(self, mock_log_source):
        toolkit = InvestigationToolkit(log_sources=[mock_log_source])

        with patch("shieldops.agents.investigation.tools.logger") as mock_logger:
            await toolkit.query_logs("default/api-server")

            # Should have at least one investigation.audit log call
            audit_calls = [
                c
                for c in mock_logger.info.call_args_list
                if c.args and c.args[0] == "investigation.audit"
            ]
            assert len(audit_calls) >= 1
            # Verify the audit call has the expected kwargs
            audit_kwargs = audit_calls[0].kwargs
            assert audit_kwargs["action"] == "query_logs"
            assert audit_kwargs["target"] == "default/api-server"
            assert audit_kwargs["result"] == "completed"

    @pytest.mark.asyncio
    async def test_query_metrics_emits_audit_log(self, mock_metric_source):
        toolkit = InvestigationToolkit(metric_sources=[mock_metric_source])

        with patch("shieldops.agents.investigation.tools.logger") as mock_logger:
            await toolkit.query_metrics("default/api-server")

            audit_calls = [
                c
                for c in mock_logger.info.call_args_list
                if c.args and c.args[0] == "investigation.audit"
            ]
            assert len(audit_calls) >= 1
            assert audit_calls[0].kwargs["action"] == "query_metrics"

    @pytest.mark.asyncio
    async def test_query_traces_emits_audit_log(self):
        trace_source = AsyncMock()
        trace_source.source_name = "jaeger"
        trace_source.search_traces = AsyncMock(return_value=[])
        trace_source.find_bottleneck = AsyncMock(return_value=None)

        toolkit = InvestigationToolkit(trace_sources=[trace_source])

        with patch("shieldops.agents.investigation.tools.logger") as mock_logger:
            await toolkit.query_traces("api-service")

            audit_calls = [
                c
                for c in mock_logger.info.call_args_list
                if c.args and c.args[0] == "investigation.audit"
            ]
            assert len(audit_calls) >= 1
            assert audit_calls[0].kwargs["action"] == "query_traces"

    @pytest.mark.asyncio
    async def test_get_k8s_events_emits_audit_log(self, mock_connector_router):
        toolkit = InvestigationToolkit(connector_router=mock_connector_router)

        with patch("shieldops.agents.investigation.tools.logger") as mock_logger:
            await toolkit.get_k8s_events("default/api-server")

            audit_calls = [
                c
                for c in mock_logger.info.call_args_list
                if c.args and c.args[0] == "investigation.audit"
            ]
            assert len(audit_calls) >= 1
            assert audit_calls[0].kwargs["action"] == "get_k8s_events"

    @pytest.mark.asyncio
    async def test_get_resource_health_emits_audit_log(self, mock_connector_router):
        toolkit = InvestigationToolkit(connector_router=mock_connector_router)

        with patch("shieldops.agents.investigation.tools.logger") as mock_logger:
            await toolkit.get_resource_health("default/api-server")

            audit_calls = [
                c
                for c in mock_logger.info.call_args_list
                if c.args and c.args[0] == "investigation.audit"
            ]
            assert len(audit_calls) >= 1
            assert audit_calls[0].kwargs["action"] == "get_resource_health"


# ============================================================================
# Graceful fallback tests
# ============================================================================


class TestGracefulFallbacks:
    """Verify toolkit methods handle missing connectors gracefully."""

    @pytest.mark.asyncio
    async def test_query_logs_no_sources_returns_empty(self):
        toolkit = InvestigationToolkit()
        result = await toolkit.query_logs("default/pod")

        assert result["total_entries"] == 0
        assert result["error_count"] == 0
        assert result["sources_queried"] == []

    @pytest.mark.asyncio
    async def test_query_logs_source_exception_handled(self):
        source = AsyncMock()
        source.source_name = "broken"
        source.query_logs = AsyncMock(side_effect=ConnectionError("Connection refused"))

        toolkit = InvestigationToolkit(log_sources=[source])
        result = await toolkit.query_logs("default/pod")

        assert result["total_entries"] == 0  # Graceful fallback

    @pytest.mark.asyncio
    async def test_query_metrics_no_sources_returns_empty(self):
        toolkit = InvestigationToolkit()
        result = await toolkit.query_metrics("default/pod")

        assert result["anomaly_count"] == 0
        assert result["sources_queried"] == []

    @pytest.mark.asyncio
    async def test_query_traces_no_sources_returns_empty(self):
        toolkit = InvestigationToolkit()
        result = await toolkit.query_traces("api-service")

        assert result["traces"] == []
        assert result["bottleneck"] is None

    @pytest.mark.asyncio
    async def test_get_k8s_events_no_router(self):
        toolkit = InvestigationToolkit()
        result = await toolkit.get_k8s_events("default/pod")
        assert result == []

    @pytest.mark.asyncio
    async def test_get_resource_health_no_router(self):
        toolkit = InvestigationToolkit()
        result = await toolkit.get_resource_health("default/pod")
        assert result["healthy"] is None
        assert result["status"] == "unknown"

    @pytest.mark.asyncio
    async def test_get_detection_context_no_router(self):
        toolkit = InvestigationToolkit()
        result = await toolkit.get_detection_context("alert-001")
        assert result["available"] is False

    @pytest.mark.asyncio
    async def test_get_detection_context_crowdstrike_unavailable(self):
        router = MagicMock()
        router.get = MagicMock(side_effect=ValueError("No crowdstrike connector"))

        toolkit = InvestigationToolkit(connector_router=router)
        result = await toolkit.get_detection_context("alert-001", "default/pod")

        assert result["available"] is False
        assert "crowdstrike" in result["reason"].lower() or "No" in result["reason"]

    @pytest.mark.asyncio
    async def test_query_historical_patterns_no_repository(self):
        toolkit = InvestigationToolkit()
        result = await toolkit.query_historical_patterns("KubePodCrashLooping")
        assert result == []


# ============================================================================
# LLM root cause analysis tests
# ============================================================================


class TestLLMRootCauseAnalysis:
    """Test LLM-powered root cause analysis with fallback."""

    @pytest.mark.asyncio
    async def test_analyze_root_cause_success(self):
        from shieldops.agents.investigation.tools import _RootCauseAnalysis

        toolkit = InvestigationToolkit()

        mock_result = _RootCauseAnalysis(
            summary="Memory leak in api-server",
            probable_root_cause="Unbounded cache growth in request handler",
            contributing_factors=["No memory limits set", "High traffic spike"],
            confidence=0.88,
            recommended_next_steps=["Set memory limits", "Fix cache eviction"],
        )

        with patch(
            "shieldops.agents.investigation.tools.llm_structured",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            result = await toolkit.analyze_root_cause(
                alert_context={"alert_name": "OOMKill", "severity": "critical"},
                findings={"error_count": 15, "anomaly_count": 3},
            )

        assert result["source"] == "llm"
        assert result["confidence"] == 0.88
        assert "cache" in result["probable_root_cause"].lower()
        assert len(result["contributing_factors"]) == 2

    @pytest.mark.asyncio
    async def test_analyze_root_cause_llm_failure_fallback(self):
        toolkit = InvestigationToolkit()

        with patch(
            "shieldops.agents.investigation.tools.llm_structured",
            new_callable=AsyncMock,
            side_effect=Exception("LLM service unavailable"),
        ):
            result = await toolkit.analyze_root_cause(
                alert_context={"alert_name": "OOMKill", "severity": "critical"},
                findings={"error_count": 15, "anomaly_count": 3},
            )

        assert result["source"] == "fallback"
        assert result["confidence"] == 0.0
        assert "LLM unavailable" in result["summary"]
        assert "15 errors" in result["summary"]
        assert "3 anomalies" in result["summary"]
        assert "Manual review required" in result["recommended_next_steps"]

    @pytest.mark.asyncio
    async def test_analyze_root_cause_emits_audit_log(self):
        toolkit = InvestigationToolkit()

        with (
            patch(
                "shieldops.agents.investigation.tools.llm_structured",
                new_callable=AsyncMock,
                side_effect=Exception("fail"),
            ),
            patch("shieldops.agents.investigation.tools.logger") as mock_logger,
        ):
            await toolkit.analyze_root_cause(
                alert_context={"alert_name": "TestAlert"},
                findings={},
            )

            audit_calls = [
                c
                for c in mock_logger.info.call_args_list
                if c.args and c.args[0] == "investigation.audit"
            ]
            assert len(audit_calls) >= 1
            assert audit_calls[-1].kwargs["action"] == "analyze_root_cause"


# ============================================================================
# CrowdStrike detection context tests
# ============================================================================


class TestDetectionContext:
    """Test CrowdStrike detection enrichment."""

    @pytest.mark.asyncio
    async def test_get_detection_context_success(self):
        cs_connector = AsyncMock()
        cs_connector.get_detections = AsyncMock(
            return_value=[
                {"detection_id": "det-001", "severity": "high", "tactic": "Lateral Movement"},
            ]
        )

        router = MagicMock()
        router.get = MagicMock(return_value=cs_connector)

        toolkit = InvestigationToolkit(connector_router=router)
        result = await toolkit.get_detection_context("alert-001", "default/api-server")

        assert result["available"] is True
        assert len(result["detections"]) == 1
        assert result["source"] == "crowdstrike"


# ============================================================================
# OPA policy integration tests (runner level)
# ============================================================================


class TestRunnerPolicyIntegration:
    """Test OPA policy checks in the investigation runner."""

    @pytest.mark.asyncio
    async def test_investigate_without_policy_engine(self, alert_context):
        """Investigation should proceed normally when no policy engine is configured."""
        from shieldops.agents.investigation.runner import InvestigationRunner

        runner = InvestigationRunner()

        mock_state = InvestigationState(
            alert_id=alert_context.alert_id,
            alert_context=alert_context,
            investigation_start=datetime.now(UTC),
            current_step="complete",
            confidence_score=0.85,
        )
        runner._app = AsyncMock()
        runner._app.ainvoke = AsyncMock(return_value=mock_state.model_dump())

        result = await runner.investigate(alert_context)
        assert result.current_step == "complete"

    @pytest.mark.asyncio
    async def test_investigate_policy_denied(self, alert_context):
        """Investigation should be blocked when OPA policy denies it."""
        from shieldops.agents.investigation.runner import InvestigationRunner
        from shieldops.policy.opa.client import PolicyDecision

        mock_policy = AsyncMock()
        mock_policy.evaluate = AsyncMock(
            return_value=PolicyDecision(
                allowed=False,
                reasons=["Investigation denied: resource under lockdown"],
            )
        )

        runner = InvestigationRunner(policy_engine=mock_policy)

        result = await runner.investigate(alert_context)

        assert result.current_step == "policy_denied"
        assert "Policy denied" in result.error

    @pytest.mark.asyncio
    async def test_investigate_policy_allowed(self, alert_context):
        """Investigation should proceed when OPA policy allows it."""
        from shieldops.agents.investigation.runner import InvestigationRunner
        from shieldops.policy.opa.client import PolicyDecision

        mock_policy = AsyncMock()
        mock_policy.evaluate = AsyncMock(return_value=PolicyDecision(allowed=True))

        runner = InvestigationRunner(policy_engine=mock_policy)

        mock_state = InvestigationState(
            alert_id=alert_context.alert_id,
            alert_context=alert_context,
            investigation_start=datetime.now(UTC),
            current_step="complete",
        )
        runner._app = AsyncMock()
        runner._app.ainvoke = AsyncMock(return_value=mock_state.model_dump())

        result = await runner.investigate(alert_context)
        assert result.current_step == "complete"
        mock_policy.evaluate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_investigate_policy_error_fails_open(self, alert_context):
        """Policy evaluation error should not block read-only investigations."""
        from shieldops.agents.investigation.runner import InvestigationRunner

        mock_policy = AsyncMock()
        mock_policy.evaluate = AsyncMock(side_effect=Exception("OPA unreachable"))

        runner = InvestigationRunner(policy_engine=mock_policy)

        mock_state = InvestigationState(
            alert_id=alert_context.alert_id,
            alert_context=alert_context,
            investigation_start=datetime.now(UTC),
            current_step="complete",
        )
        runner._app = AsyncMock()
        runner._app.ainvoke = AsyncMock(return_value=mock_state.model_dump())

        # Should NOT raise — investigation proceeds despite policy error
        result = await runner.investigate(alert_context)
        assert result.current_step == "complete"


# ============================================================================
# Audit trail tests (runner level)
# ============================================================================


class TestRunnerAuditTrail:
    """Test audit trail logging on investigation completion."""

    @pytest.mark.asyncio
    async def test_completed_investigation_emits_audit_log(self, alert_context):
        from shieldops.agents.investigation.runner import InvestigationRunner

        runner = InvestigationRunner()

        mock_state = InvestigationState(
            alert_id=alert_context.alert_id,
            alert_context=alert_context,
            investigation_start=datetime.now(UTC),
            current_step="complete",
            confidence_score=0.9,
        )
        runner._app = AsyncMock()
        runner._app.ainvoke = AsyncMock(return_value=mock_state.model_dump())

        with patch("shieldops.agents.investigation.runner.logger") as mock_logger:
            await runner.investigate(alert_context)

            audit_calls = [
                c
                for c in mock_logger.info.call_args_list
                if c.args and c.args[0] == "investigation.audit"
            ]
            assert len(audit_calls) >= 1
            audit_kwargs = audit_calls[0].kwargs
            assert audit_kwargs["action"] == "investigate"
            assert audit_kwargs["result"] == "completed"
            assert audit_kwargs["target"] == alert_context.alert_id

    @pytest.mark.asyncio
    async def test_failed_investigation_emits_audit_log(self, alert_context):
        from shieldops.agents.investigation.runner import InvestigationRunner

        runner = InvestigationRunner()
        runner._app = AsyncMock()
        runner._app.ainvoke = AsyncMock(side_effect=RuntimeError("Graph exploded"))

        with patch("shieldops.agents.investigation.runner.logger") as mock_logger:
            await runner.investigate(alert_context)

            audit_calls = [
                c
                for c in mock_logger.info.call_args_list
                if c.args and c.args[0] == "investigation.audit"
            ]
            assert len(audit_calls) >= 1
            audit_kwargs = audit_calls[0].kwargs
            assert audit_kwargs["action"] == "investigate"
            assert audit_kwargs["result"] == "failed"


# ============================================================================
# Splunk connector integration tests
# ============================================================================


class TestSplunkIntegration:
    """Test Splunk connector usage in query_logs."""

    @pytest.mark.asyncio
    async def test_query_logs_tries_splunk(self):
        splunk_connector = AsyncMock()
        splunk_connector.search = AsyncMock(
            return_value=[
                {"message": "Splunk log entry", "level": "error"},
            ]
        )

        router = MagicMock()
        router.get = MagicMock(return_value=splunk_connector)

        toolkit = InvestigationToolkit(connector_router=router)
        result = await toolkit.query_logs("default/api-server")

        assert result["total_entries"] == 1
        assert result["error_count"] == 1
        router.get.assert_any_call("splunk")

    @pytest.mark.asyncio
    async def test_query_logs_splunk_unavailable_falls_back(self, mock_log_source):
        router = MagicMock()
        router.get = MagicMock(side_effect=ValueError("No splunk connector"))

        toolkit = InvestigationToolkit(
            connector_router=router,
            log_sources=[mock_log_source],
        )
        result = await toolkit.query_logs("default/api-server")

        # Should still get results from log sources
        assert result["total_entries"] == 2
