"""OTel Pipeline Agent — Node function implementations."""

from __future__ import annotations

from typing import Any, cast

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import (
    CollectorConfig,
    CollectorMode,
    InstrumentationTarget,
    PipelineComponent,
    PipelineHealthMetric,
    PipelineStage,
)
from .prompts import SYSTEM_VALIDATE
from .tools import OTelPipelineToolkit

logger = structlog.get_logger()


class _ValidationLLMResult(BaseModel):
    """Structured LLM output for pipeline validation."""

    valid: bool = Field(description="Whether the pipeline configuration is valid")
    issues: list[str] = Field(description="List of issues found in the configuration")
    recommendations: list[str] = Field(description="Recommendations for improving the config")
    confidence: float = Field(description="Confidence score for the validation (0.0-1.0)")


async def discover_pipeline(state: dict[str, Any], toolkit: OTelPipelineToolkit) -> dict[str, Any]:
    """Discover existing OTel infrastructure and uninstrumented services."""
    logger.info("otel_pipeline.node.discover")
    cluster = state.get("cluster_name", "")
    namespace = state.get("namespace", "default")

    services = await toolkit.discover_services(cluster, namespace)
    topics = await toolkit.list_kafka_topics("otel.*")

    uninstrumented = [s for s in services if not s.get("instrumented")]
    instrumentation_targets = [
        InstrumentationTarget(
            service_name=s["name"],
            namespace=s.get("namespace", namespace),
            language=s.get("language", "python"),
        ).model_dump()
        for s in uninstrumented
    ]

    reasoning = [
        f"Discovered {len(services)} services in {namespace}",
        f"{len(uninstrumented)} services lack OTel instrumentation",
        f"Found {len(topics)} Kafka topics with telemetry data",
    ]

    return {
        "stage": PipelineStage.CONFIGURE.value,
        "discovered_services": services,
        "instrumentation_targets": instrumentation_targets,
        "kafka_topics": [t["topic"] for t in topics],
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def configure_pipeline(state: dict[str, Any], toolkit: OTelPipelineToolkit) -> dict[str, Any]:
    """Generate optimal collector configuration."""
    logger.info("otel_pipeline.node.configure")
    topics = state.get("kafka_topics", [])
    exporters = state.get("exporter_targets", ["otlp"])

    config = await toolkit.generate_collector_config(
        mode="daemonset",
        kafka_topics=topics if topics else None,
        exporters=exporters if exporters else None,
    )

    target_config = CollectorConfig(
        collector_id=f"otel-{state.get('cluster_name', 'default')}",
        mode=CollectorMode.DAEMONSET,
        receivers=[
            PipelineComponent(name=k, component_type="receiver", config=v)
            for k, v in config.get("config", {}).get("receivers", {}).items()
        ],
        processors=[
            PipelineComponent(name=k, component_type="processor", config=v)
            for k, v in config.get("config", {}).get("processors", {}).items()
        ],
        exporters=[
            PipelineComponent(name=k, component_type="exporter", config=v)
            for k, v in config.get("config", {}).get("exporters", {}).items()
        ],
        resource_limits=config.get("resources", {}),
    )

    reasoning = [
        f"Configured {target_config.mode.value} collector with "
        f"{len(target_config.receivers)} receivers, "
        f"{len(target_config.processors)} processors, "
        f"{len(target_config.exporters)} exporters",
    ]

    return {
        "stage": PipelineStage.VALIDATE.value,
        "target_config": target_config.model_dump(),
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def validate_pipeline(state: dict[str, Any], toolkit: OTelPipelineToolkit) -> dict[str, Any]:
    """Validate the generated pipeline configuration."""
    logger.info("otel_pipeline.node.validate")
    target_config = state.get("target_config", {})

    # Re-structure for validation
    config_for_validation = {
        "config": {
            "receivers": {c["name"]: c["config"] for c in target_config.get("receivers", [])},
            "processors": {c["name"]: c["config"] for c in target_config.get("processors", [])},
            "exporters": {c["name"]: c["config"] for c in target_config.get("exporters", [])},
            "service": {
                "pipelines": {
                    "traces": {
                        "receivers": [c["name"] for c in target_config.get("receivers", [])],
                        "processors": [c["name"] for c in target_config.get("processors", [])],
                        "exporters": [c["name"] for c in target_config.get("exporters", [])],
                    }
                }
            },
        },
        "resources": target_config.get("resource_limits", {}),
    }

    result = await toolkit.validate_pipeline_config(config_for_validation)

    reasoning = []
    llm_enhanced = False

    # LLM enhancement: deeper validation analysis
    try:
        import json

        config_summary = json.dumps(config_for_validation, indent=2, default=str)
        user_prompt = (
            f"Validate this OTel pipeline configuration:\n{config_summary}\n\n"
            f"Toolkit validation result: valid={result['valid']}, "
            f"errors={result.get('errors', [])}, warnings={result.get('warnings', [])}"
        )
        llm_result = cast(
            _ValidationLLMResult,
            await llm_structured(
                system_prompt=SYSTEM_VALIDATE,
                user_prompt=user_prompt,
                schema=_ValidationLLMResult,
            ),
        )
        llm_enhanced = True
        logger.info(
            "llm_enhanced",
            node="validate_pipeline",
            llm_valid=llm_result.valid,
            llm_confidence=llm_result.confidence,
        )
        if llm_result.recommendations:
            reasoning.extend(llm_result.recommendations)
        if llm_result.issues:
            reasoning.append(f"LLM issues: {', '.join(llm_result.issues)}")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="validate_pipeline")

    if result["valid"]:
        reasoning.append("Pipeline configuration is valid")
    else:
        reasoning.append(f"Validation failed: {', '.join(result['errors'])}")
    if result.get("warnings"):
        reasoning.append(f"Warnings: {', '.join(result['warnings'])}")

    next_stage = PipelineStage.DEPLOY.value if result["valid"] else PipelineStage.CONFIGURE.value

    return {
        "stage": next_stage,
        "config_valid": result["valid"],
        "validation_errors": result.get("errors", []),
        "llm_enhanced": llm_enhanced,
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def monitor_pipeline(state: dict[str, Any], toolkit: OTelPipelineToolkit) -> dict[str, Any]:
    """Monitor deployed pipeline health and generate recommendations."""
    logger.info("otel_pipeline.node.monitor")
    target_config = state.get("target_config", {})
    collector_id = target_config.get("collector_id", "")

    health = await toolkit.get_collector_health(collector_id)
    metric = PipelineHealthMetric(**health)

    recommendations: list[str] = []
    if metric.dropped_spans > 0:
        recommendations.append(
            f"Collector {collector_id} dropping spans — increase batch size or scale out"
        )
    if metric.queue_depth > 1000:
        recommendations.append(
            f"Queue depth {metric.queue_depth} — consider adding memory_limiter backpressure"
        )
    if metric.export_latency_ms > 500:
        recommendations.append(
            f"Export latency {metric.export_latency_ms}ms — check backend health"
        )
    if not recommendations:
        recommendations.append("Pipeline operating within healthy parameters")

    score = 1.0
    if metric.dropped_spans > 0:
        score -= 0.2
    if metric.queue_depth > 1000:
        score -= 0.2
    if metric.export_latency_ms > 500:
        score -= 0.2

    final_score = round(max(score, 0.0), 2)

    return {
        "stage": PipelineStage.MONITOR.value,
        "health_metrics": [metric.model_dump()],
        "pipeline_score": final_score,
        "recommendations": recommendations,
        "confidence_score": final_score,
        "reasoning_chain": state.get("reasoning_chain", []) + [f"Pipeline score: {final_score}"],
    }
