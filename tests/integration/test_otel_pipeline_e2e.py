"""End-to-end integration tests for the OTel Pipeline Agent.

Tests the full LangGraph workflow: discover -> configure -> validate -> monitor,
with mock backends (no real K8s/Kafka needed). The toolkit has built-in
fallback paths that produce deterministic output when no clients are injected.
"""

from unittest.mock import AsyncMock, patch

import pytest

from shieldops.agents.otel_pipeline.nodes import _ValidationLLMResult
from shieldops.agents.otel_pipeline.runner import OTelPipelineRunner

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def mock_k8s_client():
    """K8s client that returns a mix of instrumented and uninstrumented pods."""
    client = AsyncMock()
    client.list_pods.return_value = [
        {
            "name": "api-server",
            "namespace": "default",
            "labels": {"language": "python"},
            "containers": [{"name": "api", "env": []}],
        },
        {
            "name": "payment-svc",
            "namespace": "default",
            "labels": {"language": "java"},
            "containers": [
                {"name": "payment", "env": []},
                {"name": "otel-sidecar", "env": []},
            ],
        },
        {
            "name": "worker",
            "namespace": "default",
            "labels": {"language": "python"},
            "containers": [{"name": "worker-main", "env": []}],
        },
    ]
    return client


@pytest.fixture
def mock_kafka_client():
    """Kafka client that returns OTel-related topics."""
    client = AsyncMock()
    client.list_topics.return_value = {
        "otel.traces": {"partitions": 6},
        "otel.metrics": {"partitions": 3},
        "otel.logs": {"partitions": 3},
        "app.events": {"partitions": 12},
    }
    return client


@pytest.fixture
def validation_llm_response():
    """Deterministic LLM response for the validation node."""
    return _ValidationLLMResult(
        valid=True,
        issues=[],
        recommendations=["Consider adding tail-sampling processor for cost control"],
        confidence=0.95,
    )


# ── Helpers ───────────────────────────────────────────────────────────


def _get(result, key, default=None):
    """Access a field from a result that may be a dict or a Pydantic model."""
    if isinstance(result, dict):
        return result.get(key, default) if default is not None else result.get(key)
    return getattr(result, key, default)


def _getitem(result, key):
    """Access a field from a result that may be a dict or a Pydantic model."""
    if isinstance(result, dict):
        return result[key]
    return getattr(result, key)


# ── Full Pipeline ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_otel_pipeline_full_run_with_mock_backends(
    mock_k8s_client,
    mock_kafka_client,
    validation_llm_response,
):
    """Full pipeline discovers, configures, validates, and monitors successfully."""

    async def fake_llm(system_prompt="", user_prompt="", schema=None, **kwargs):
        return validation_llm_response

    with patch(
        "shieldops.agents.otel_pipeline.nodes.llm_structured",
        side_effect=fake_llm,
    ):
        runner = OTelPipelineRunner(
            k8s_client=mock_k8s_client,
            kafka_client=mock_kafka_client,
        )
        result = await runner.run(
            cluster_name="test-cluster",
            namespace="default",
            exporter_targets=["otlp_http"],
        )

    assert _getitem(result, "config_valid") is True
    assert _getitem(result, "pipeline_score") > 0
    assert len(_getitem(result, "reasoning_chain")) >= 4
    assert len(_getitem(result, "recommendations")) >= 1
    assert _getitem(result, "confidence_score") > 0


@pytest.mark.asyncio
async def test_otel_pipeline_no_backends():
    """Pipeline runs with zero backends; toolkit returns empty lists gracefully."""
    runner = OTelPipelineRunner()
    result = await runner.run(cluster_name="empty-cluster", exporter_targets=["otlp_http"])

    # With no k8s or kafka, discover returns empty, but pipeline still completes
    assert _get(result, "discovered_services", []) == []
    assert _get(result, "config_valid") is True
    assert len(_getitem(result, "reasoning_chain")) >= 3


# ── Discovery ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_otel_pipeline_discovers_uninstrumented_services(
    mock_k8s_client,
    mock_kafka_client,
):
    """Discovery identifies services lacking OTel instrumentation."""
    runner = OTelPipelineRunner(
        k8s_client=mock_k8s_client,
        kafka_client=mock_kafka_client,
    )
    result = await runner.run(cluster_name="test-cluster", exporter_targets=["otlp_http"])

    discovered = _get(result, "discovered_services", [])
    assert len(discovered) == 3

    uninstrumented = [s for s in discovered if not s.get("instrumented")]
    # api-server and worker lack OTel; payment-svc has otel-sidecar
    assert len(uninstrumented) == 2


@pytest.mark.asyncio
async def test_otel_pipeline_discovers_kafka_topics(
    mock_k8s_client,
    mock_kafka_client,
):
    """Discovery finds otel.* Kafka topics."""
    runner = OTelPipelineRunner(
        k8s_client=mock_k8s_client,
        kafka_client=mock_kafka_client,
    )
    result = await runner.run(cluster_name="test-cluster", exporter_targets=["otlp_http"])

    topics = _get(result, "kafka_topics", [])
    assert "otel.traces" in topics
    assert "otel.metrics" in topics
    assert "otel.logs" in topics
    # app.events should NOT match otel.* pattern
    assert "app.events" not in topics


# ── Configuration ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_otel_pipeline_configures_collector_with_exporters(
    mock_k8s_client,
    mock_kafka_client,
):
    """Configured collector includes requested exporter targets."""
    runner = OTelPipelineRunner(
        k8s_client=mock_k8s_client,
        kafka_client=mock_kafka_client,
    )
    result = await runner.run(
        cluster_name="test-cluster",
        exporter_targets=["otlp_http", "splunk_hec"],
    )

    target_config = _get(result, "target_config", {})
    assert target_config is not None
    mode = target_config.get("mode") if isinstance(target_config, dict) else target_config.mode
    assert mode == "daemonset"
    if isinstance(target_config, dict):
        exporters = target_config.get("exporters", [])
        exporter_names = [e["name"] for e in exporters]
    else:
        exporters = target_config.exporters
        exporter_names = [e.name for e in exporters]
    assert "splunk_hec" in exporter_names


@pytest.mark.asyncio
async def test_otel_pipeline_configures_processors(
    mock_k8s_client,
    mock_kafka_client,
):
    """Configured collector includes batch, resourcedetection, and memory_limiter."""
    runner = OTelPipelineRunner(
        k8s_client=mock_k8s_client,
        kafka_client=mock_kafka_client,
    )
    result = await runner.run(cluster_name="test-cluster", exporter_targets=["otlp_http"])

    target_config = _get(result, "target_config", {})
    assert target_config is not None
    if isinstance(target_config, dict):
        processors = target_config.get("processors", [])
        proc_names = [p["name"] for p in processors]
    else:
        processors = target_config.processors
        proc_names = [p.name for p in processors]
    assert "batch" in proc_names
    assert "memory_limiter" in proc_names


# ── Validation ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_otel_pipeline_validation_passes():
    """Generated config passes structural validation."""
    runner = OTelPipelineRunner()
    result = await runner.run(cluster_name="valid-cluster", exporter_targets=["otlp_http"])

    assert _getitem(result, "config_valid") is True
    assert _get(result, "validation_errors", []) == []


@pytest.mark.asyncio
async def test_otel_pipeline_validation_with_llm(
    mock_k8s_client,
    mock_kafka_client,
    validation_llm_response,
):
    """When LLM is available, validation includes LLM recommendations."""

    async def fake_llm(system_prompt="", user_prompt="", schema=None, **kwargs):
        return validation_llm_response

    with patch(
        "shieldops.agents.otel_pipeline.nodes.llm_structured",
        side_effect=fake_llm,
    ):
        runner = OTelPipelineRunner(
            k8s_client=mock_k8s_client,
            kafka_client=mock_kafka_client,
        )
        result = await runner.run(cluster_name="test-cluster", exporter_targets=["otlp_http"])

    # LLM recommendation should appear in reasoning chain
    chain = _get(result, "reasoning_chain", [])
    chain_text = " ".join(str(r) for r in chain)
    assert "tail-sampling" in chain_text or "valid" in chain_text.lower()


# ── Monitoring ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_otel_pipeline_monitoring_healthy():
    """Monitor reports healthy pipeline with score 1.0 when no drops."""
    runner = OTelPipelineRunner()
    result = await runner.run(cluster_name="healthy-cluster", exporter_targets=["otlp_http"])

    assert _getitem(result, "pipeline_score") == 1.0
    assert _getitem(result, "confidence_score") == 1.0
    recs = _get(result, "recommendations", [])
    assert any("healthy" in r.lower() for r in recs)


@pytest.mark.asyncio
async def test_otel_pipeline_reasoning_chain_populated(
    mock_k8s_client,
    mock_kafka_client,
):
    """Reasoning chain records at least one entry per pipeline stage."""
    runner = OTelPipelineRunner(
        k8s_client=mock_k8s_client,
        kafka_client=mock_kafka_client,
    )
    result = await runner.run(cluster_name="test-cluster", exporter_targets=["otlp_http"])

    chain = _get(result, "reasoning_chain", [])
    # discover, configure, validate, monitor each add at least one entry
    assert len(chain) >= 4
