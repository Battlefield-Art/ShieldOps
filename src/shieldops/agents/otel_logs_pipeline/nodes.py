"""OTel Logs Pipeline Agent — Node function implementations."""

from __future__ import annotations

from typing import Any

import structlog

from .models import (
    LogEndpoint,
    LogParsingResult,
    LogPipelineConfig,
    LogStage,
)
from .tools import OTelLogsPipelineToolkit

logger = structlog.get_logger()


async def discover_sources(
    state: dict[str, Any],
    toolkit: OTelLogsPipelineToolkit,
) -> dict[str, Any]:
    """Discover log sources in the target namespace."""
    logger.info("otel_logs_pipeline.node.discover_sources")
    namespace = state.get("target_namespace", "default")

    endpoints = await toolkit.discover_log_sources(namespace)

    reasoning = [
        f"Discovered log sources in namespace '{namespace}'",
        f"Found {len(endpoints)} log sources",
    ]
    for ep in endpoints:
        reasoning.append(
            f"  {ep.service}: {ep.source.value} at {ep.path_or_endpoint} "
            f"({ep.format.value}, ~{ep.volume_per_min} logs/min)"
        )

    return {
        "stage": LogStage.CONFIGURE.value,
        "endpoints": [ep.model_dump() for ep in endpoints],
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def configure_pipeline(
    state: dict[str, Any],
    toolkit: OTelLogsPipelineToolkit,
) -> dict[str, Any]:
    """Configure the logs pipeline based on discovered endpoints."""
    logger.info("otel_logs_pipeline.node.configure_pipeline")

    raw_endpoints = state.get("endpoints", [])
    endpoints = [LogEndpoint(**ep) if isinstance(ep, dict) else ep for ep in raw_endpoints]

    config = toolkit.configure_log_pipeline(endpoints)

    reasoning = [
        f"Configured logs pipeline with {len(config.receivers)} receivers, "
        f"{len(config.processors)} processors, {len(config.exporters)} exporters",
        f"Receivers: {', '.join(config.receivers)}",
        f"Processors: {', '.join(config.processors)}",
        f"Exporters: {', '.join(config.exporters)}",
        f"Resource attributes: {config.resource_attributes}",
    ]

    return {
        "stage": LogStage.PARSE.value,
        "pipeline_config": config.model_dump(),
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def test_parsing(
    state: dict[str, Any],
    toolkit: OTelLogsPipelineToolkit,
) -> dict[str, Any]:
    """Test log parsing rules for each service."""
    logger.info("otel_logs_pipeline.node.test_parsing")

    raw_endpoints = state.get("endpoints", [])
    endpoints = [LogEndpoint(**ep) if isinstance(ep, dict) else ep for ep in raw_endpoints]

    results: list[LogParsingResult] = []
    reasoning: list[str] = []

    services_seen: set[str] = set()
    for ep in endpoints:
        if ep.service in services_seen:
            continue
        services_seen.add(ep.service)

        result = toolkit.test_log_parsing(ep.service)
        results.append(result)
        error_info = f" — errors: {result.sample_errors}" if result.sample_errors else ""
        reasoning.append(
            f"Parsing for {result.service}: {result.parsed_pct:.1f}% success, "
            f"{result.failed_pct:.1f}% failed{error_info}"
        )

    return {
        "stage": LogStage.VALIDATE.value,
        "parsing_results": [r.model_dump() for r in results],
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def validate_correlation(
    state: dict[str, Any],
    toolkit: OTelLogsPipelineToolkit,
) -> dict[str, Any]:
    """Validate trace-log correlation and generate final pipeline YAML."""
    logger.info("otel_logs_pipeline.node.validate_correlation")
    namespace = state.get("target_namespace", "default")

    correlation = toolkit.check_trace_correlation(namespace)
    overall_rate = correlation.get("overall_correlation_rate", 0.0)

    reasoning: list[str] = [
        f"Trace-log correlation rate: {overall_rate:.0%}",
    ]

    services_data = correlation.get("services", {})
    for svc, info in services_data.items():
        rate = info.get("correlation_rate", 0.0)
        has_trace = info.get("has_trace_id", False)
        status = "OK" if rate >= 0.80 else "LOW"
        trace_status = "has trace_id" if has_trace else "NO trace_id"
        reasoning.append(f"  {svc}: {rate:.0%} correlation ({trace_status}) [{status}]")

    low_services = [
        svc for svc, info in services_data.items() if info.get("correlation_rate", 0.0) < 0.80
    ]
    if low_services:
        reasoning.append(
            f"WARNING: Low correlation services: {', '.join(low_services)}. "
            "Ensure SDK context propagation is enabled."
        )
    else:
        reasoning.append("All services have good trace-log correlation.")

    # Generate pipeline YAML
    raw_config = state.get("pipeline_config")
    if raw_config:
        config = LogPipelineConfig(**raw_config) if isinstance(raw_config, dict) else raw_config
        raw_endpoints = state.get("endpoints", [])
        endpoints = [LogEndpoint(**ep) if isinstance(ep, dict) else ep for ep in raw_endpoints]
        pipeline_yaml = toolkit.generate_logs_pipeline_yaml(config, endpoints)
        reasoning.append(f"Generated OTel Collector logs YAML ({len(pipeline_yaml)} chars)")

    return {
        "trace_correlation_rate": overall_rate,
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }
