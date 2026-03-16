"""End-to-end integration tests for the OTel Collector Manager Agent.

Tests the full LangGraph workflow: assess -> generate -> deploy -> monitor,
with no real Kubernetes backend (mock fallback paths). The toolkit uses
simulated responses when no k8s_client is injected.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
import yaml

from shieldops.agents.otel_collector_manager.models import CollectorAction
from shieldops.agents.otel_collector_manager.runner import OTelCollectorManagerRunner

# ── Full Pipeline ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_full_pipeline_deploy():
    """Full pipeline runs assess -> generate -> deploy -> monitor with no backends."""
    runner = OTelCollectorManagerRunner()
    result = await runner.run(namespace="monitoring", action=CollectorAction.DEPLOY)

    assert isinstance(result, dict)
    assert not result.get("error")
    assert len(result.get("reasoning_chain", [])) >= 3
    assert result.get("health_status", {}).get("healthy") is True
    assert result.get("deployment_result", {}).get("status") == "simulated"


@pytest.mark.asyncio
async def test_full_pipeline_health_check():
    """Health check action runs the full pipeline and returns health data."""
    runner = OTelCollectorManagerRunner()
    result = await runner.run(
        namespace="default",
        action=CollectorAction.HEALTH_CHECK,
    )

    assert isinstance(result, dict)
    assert not result.get("error")
    health = result.get("health_status", {})
    assert health.get("healthy") is True
    assert health.get("namespace") == "default"


@pytest.mark.asyncio
async def test_full_pipeline_scale():
    """Scale action runs the full pipeline with scale operation."""
    runner = OTelCollectorManagerRunner()
    result = await runner.run(
        namespace="production",
        action=CollectorAction.SCALE,
    )

    assert isinstance(result, dict)
    deploy_result = result.get("deployment_result", {})
    assert deploy_result.get("status") == "simulated"
    assert deploy_result.get("namespace") == "production"


@pytest.mark.asyncio
async def test_full_pipeline_rollback():
    """Rollback action runs the full pipeline with rollback operation."""
    runner = OTelCollectorManagerRunner()
    result = await runner.run(
        namespace="staging",
        action=CollectorAction.ROLLBACK,
    )

    assert isinstance(result, dict)
    deploy_result = result.get("deployment_result", {})
    assert deploy_result.get("status") == "simulated"
    assert deploy_result.get("namespace") == "staging"


# ── Config Generation ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_config_yaml_generation_produces_valid_output():
    """Generated collector config results in valid YAML with expected structure."""
    runner = OTelCollectorManagerRunner()
    result = await runner.run(namespace="default", action=CollectorAction.DEPLOY)

    config_data = result.get("collector_config", {})
    assert isinstance(config_data, dict)
    assert len(config_data.get("receivers", [])) >= 2
    assert len(config_data.get("processors", [])) >= 2
    assert len(config_data.get("exporters", [])) >= 1
    assert len(config_data.get("pipelines", [])) >= 3

    # Verify the toolkit can generate valid YAML from this config
    from shieldops.agents.otel_collector_manager.models import CollectorConfig
    from shieldops.agents.otel_collector_manager.tools import OTelCollectorManagerToolkit

    toolkit = OTelCollectorManagerToolkit()
    config = CollectorConfig(**config_data)
    yaml_str = toolkit.generate_collector_yaml(config)
    parsed = yaml.safe_load(yaml_str)
    assert "receivers" in parsed
    assert "processors" in parsed
    assert "exporters" in parsed
    assert "service" in parsed
    assert "pipelines" in parsed["service"]


@pytest.mark.asyncio
async def test_config_includes_standard_pipelines():
    """Config contains traces, metrics, and logs pipelines."""
    runner = OTelCollectorManagerRunner()
    result = await runner.run(namespace="default", action=CollectorAction.DEPLOY)

    pipelines = result.get("collector_config", {}).get("pipelines", [])
    pipeline_names = {p.get("name", "") for p in pipelines}
    assert "traces" in pipeline_names
    assert "metrics" in pipeline_names
    assert "logs" in pipeline_names


# ── Health Monitoring ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_monitoring_returns_complete_data():
    """Monitor node returns health metrics including pods, zpages, and drops."""
    runner = OTelCollectorManagerRunner()
    result = await runner.run(namespace="default", action=CollectorAction.DEPLOY)

    health = result.get("health_status", {})
    assert "total_pods" in health
    assert "healthy_pods" in health
    assert "unhealthy_pods" in health
    assert "zpages_available" in health
    assert "dropped_spans" in health
    assert "dropped_metrics" in health
    assert "queue_depth" in health
    assert health["dropped_spans"] == 0
    assert health["queue_depth"] == 0


@pytest.mark.asyncio
async def test_deploy_with_k8s_client_mock():
    """Pipeline uses the k8s client when provided."""
    mock_k8s = AsyncMock()
    mock_k8s.apply_manifest.return_value = {"applied": True}
    mock_k8s.list_pods.return_value = [
        {"metadata": {"name": "otel-collector-abc"}, "status": {"phase": "Running"}},
        {"metadata": {"name": "otel-collector-def"}, "status": {"phase": "Running"}},
    ]

    runner = OTelCollectorManagerRunner(k8s_client=mock_k8s)
    result = await runner.run(namespace="monitoring", action=CollectorAction.DEPLOY)

    assert isinstance(result, dict)
    deploy_result = result.get("deployment_result", {})
    assert deploy_result.get("status") == "deployed"
    health = result.get("health_status", {})
    assert health.get("total_pods") == 2
    assert health.get("healthy_pods") == 2
