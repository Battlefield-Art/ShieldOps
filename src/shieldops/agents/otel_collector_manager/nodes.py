"""OTel Collector Manager Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    CollectorAction,
    CollectorConfig,
    DeploymentMode,
    ExporterConfig,
    PipelineConfig,
    PipelineType,
    ProcessorConfig,
    ReceiverConfig,
)
from .tools import OTelCollectorManagerToolkit

logger = structlog.get_logger()


async def assess_requirements(
    state: dict[str, Any],
    toolkit: OTelCollectorManagerToolkit,
) -> dict[str, Any]:
    """Determine what receivers/processors/exporters are needed."""
    logger.info("otel_collector_manager.node.assess_requirements")
    namespace = state.get("target_namespace", "default")
    action = state.get("action", CollectorAction.DEPLOY.value)

    health = await toolkit.check_collector_health(namespace)

    reasoning = [
        f"Assessing requirements for namespace '{namespace}'",
        f"Action requested: {action}",
        f"Existing collector health: {'healthy' if health.get('healthy') else 'unhealthy'}",
    ]

    return {
        "health_status": health,
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def generate_config(
    state: dict[str, Any],
    toolkit: OTelCollectorManagerToolkit,
) -> dict[str, Any]:
    """Build CollectorConfig and generate YAML."""
    logger.info("otel_collector_manager.node.generate_config")
    _action = state.get("action", CollectorAction.DEPLOY.value)

    # Default to agent mode
    mode = DeploymentMode.AGENT
    if isinstance(state.get("collector_config"), dict):
        mode_val = state["collector_config"].get("deployment_mode", "agent")
        try:
            mode = DeploymentMode(mode_val)
        except ValueError:
            mode = DeploymentMode.AGENT

    # Build a standard config with common receivers, processors, exporters
    receivers = [
        ReceiverConfig(
            name="otlp",
            type="otlp",
            protocol="grpc",
            endpoint="0.0.0.0:4317",
        ),
        ReceiverConfig(
            name="otlp/http",
            type="otlp",
            protocol="http",
            endpoint="0.0.0.0:4318",
        ),
    ]

    processors = [
        ProcessorConfig(
            name="memory_limiter",
            type="memory_limiter",
            config={"check_interval": "1s", "limit_mib": 512},
        ),
        ProcessorConfig(
            name="batch",
            type="batch",
            config={"timeout": "5s", "send_batch_size": 1024},
        ),
        ProcessorConfig(
            name="k8sattributes",
            type="k8sattributes",
            config={"passthrough": False, "extract": {"metadata": ["namespace", "pod.name"]}},
        ),
    ]

    exporters = [
        ExporterConfig(
            name="otlp/shieldops",
            type="otlp",
            endpoint="${SHIELDOPS_OTEL_ENDPOINT}",
            headers={"Authorization": "Bearer ${SHIELDOPS_API_KEY}"},
        ),
        ExporterConfig(
            name="debug",
            type="debug",
            endpoint="",
            extra_config={"verbosity": "basic"},
        ),
    ]

    pipelines = [
        PipelineConfig(
            name="traces",
            type=PipelineType.TRACES,
            receivers=["otlp", "otlp/http"],
            processors=["memory_limiter", "k8sattributes", "batch"],
            exporters=["otlp/shieldops"],
        ),
        PipelineConfig(
            name="metrics",
            type=PipelineType.METRICS,
            receivers=["otlp", "otlp/http"],
            processors=["memory_limiter", "batch"],
            exporters=["otlp/shieldops"],
        ),
        PipelineConfig(
            name="logs",
            type=PipelineType.LOGS,
            receivers=["otlp", "otlp/http"],
            processors=["memory_limiter", "batch"],
            exporters=["otlp/shieldops"],
        ),
    ]

    config = CollectorConfig(
        receivers=receivers,
        processors=processors,
        exporters=exporters,
        pipelines=pipelines,
        extensions=["zpages", "health_check"],
        deployment_mode=mode,
    )

    _yaml_output = toolkit.generate_collector_yaml(config)

    reasoning = [
        f"Generated {mode.value}-mode collector config with "
        f"{len(receivers)} receivers, {len(processors)} processors, "
        f"{len(exporters)} exporters, {len(pipelines)} pipelines",
    ]

    # LLM enhancement: intelligent config optimization advice
    try:
        from .prompts import SYSTEM_GENERATE, ConfigGenerationResult

        config_context = json.dumps(
            {
                "deployment_mode": mode.value,
                "receivers": [r.name for r in receivers],
                "processors": [p.name for p in processors],
                "exporters": [e.name for e in exporters],
                "pipelines": [p.name for p in pipelines],
            },
            default=str,
        )
        llm_result = cast(
            ConfigGenerationResult,
            await llm_structured(
                system_prompt=SYSTEM_GENERATE,
                user_prompt=f"OTel Collector config context:\n{config_context}",
                schema=ConfigGenerationResult,
            ),
        )
        logger.info("llm_enhanced", agent="otel_collector_manager", node="generate_config")
        reasoning.append(f"LLM analysis: {llm_result.summary}")
        reasoning.extend(llm_result.optimization_notes)
    except Exception:
        logger.debug("llm_fallback", agent="otel_collector_manager", node="generate_config")

    return {
        "collector_config": config.model_dump(),
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def deploy_and_verify(
    state: dict[str, Any],
    toolkit: OTelCollectorManagerToolkit,
) -> dict[str, Any]:
    """Deploy the collector and verify health."""
    logger.info("otel_collector_manager.node.deploy_and_verify")
    namespace = state.get("target_namespace", "default")
    action = state.get("action", CollectorAction.DEPLOY.value)

    config_data = state.get("collector_config")
    if config_data and isinstance(config_data, dict):
        config = CollectorConfig(**config_data)
    else:
        config = CollectorConfig()

    reasoning: list[str] = []

    if action == CollectorAction.ROLLBACK.value:
        result = await toolkit.rollback_collector(namespace, revision=1)
        reasoning.append(f"Rollback result: {result.get('status', 'unknown')}")
    elif action == CollectorAction.SCALE.value:
        result = await toolkit.scale_collectors(namespace, replicas=3)
        reasoning.append(f"Scale result: {result.get('status', 'unknown')}")
    else:
        yaml_config = toolkit.generate_collector_yaml(config)
        result = await toolkit.deploy_collector(
            namespace=namespace,
            yaml_config=yaml_config,
            mode=config.deployment_mode,
        )
        reasoning.append(f"Deploy result: {result.get('status', 'unknown')}")

    # Verify health after action
    health = await toolkit.check_collector_health(namespace)
    reasoning.append(f"Post-deploy health: {'healthy' if health.get('healthy') else 'unhealthy'}")

    return {
        "deployment_result": result,
        "health_status": health,
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def monitor_health(
    state: dict[str, Any],
    toolkit: OTelCollectorManagerToolkit,
) -> dict[str, Any]:
    """Ongoing health monitoring of the deployed collector."""
    logger.info("otel_collector_manager.node.monitor_health")
    namespace = state.get("target_namespace", "default")

    health = await toolkit.check_collector_health(namespace)

    reasoning: list[str] = []
    if health.get("healthy"):
        reasoning.append("Collector is healthy — all pods running")
    else:
        unhealthy = health.get("unhealthy_pods", 0)
        reasoning.append(f"Collector has {unhealthy} unhealthy pod(s)")

    if health.get("dropped_spans", 0) > 0:
        reasoning.append(
            f"Dropping {health['dropped_spans']} spans — consider scaling or tuning batch size"
        )

    if health.get("queue_depth", 0) > 1000:
        reasoning.append(f"Queue depth {health['queue_depth']} — backpressure detected")

    return {
        "health_status": health,
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }
