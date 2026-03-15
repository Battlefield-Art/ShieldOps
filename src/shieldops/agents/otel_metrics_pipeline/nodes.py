"""OTel Metrics Pipeline Agent — Node function implementations."""

from __future__ import annotations

from typing import Any

import structlog

from .models import (
    CardinalityReport,
    MetricEndpoint,
    MetricPipelineConfig,
    MetricStage,
)
from .tools import OTelMetricsPipelineToolkit

logger = structlog.get_logger()


async def discover_endpoints(
    state: dict[str, Any],
    toolkit: OTelMetricsPipelineToolkit,
) -> dict[str, Any]:
    """Discover metric endpoints in the target namespace."""
    logger.info("otel_metrics_pipeline.node.discover_endpoints")
    namespace = state.get("target_namespace", "default")

    endpoints = await toolkit.discover_metric_endpoints(namespace)

    reasoning = [
        f"Discovered metric endpoints in namespace '{namespace}'",
        f"Found {len(endpoints)} metric sources",
    ]
    for ep in endpoints:
        reasoning.append(
            f"  {ep.service}: {ep.source.value} at {ep.endpoint} "
            f"({ep.metric_count} metrics, {ep.scrape_interval_s}s interval)"
        )

    return {
        "stage": MetricStage.CONFIGURE.value,
        "endpoints": [ep.model_dump() for ep in endpoints],
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def configure_pipeline(
    state: dict[str, Any],
    toolkit: OTelMetricsPipelineToolkit,
) -> dict[str, Any]:
    """Configure the metrics pipeline based on discovered endpoints."""
    logger.info("otel_metrics_pipeline.node.configure_pipeline")

    raw_endpoints = state.get("endpoints", [])
    endpoints = [MetricEndpoint(**ep) if isinstance(ep, dict) else ep for ep in raw_endpoints]

    config = toolkit.configure_pipeline(endpoints)

    reasoning = [
        f"Configured metrics pipeline with {len(config.receivers)} receivers, "
        f"{len(config.processors)} processors, {len(config.exporters)} exporters",
        f"Receivers: {', '.join(config.receivers)}",
        f"Processors: {', '.join(config.processors)}",
        f"Exporters: {', '.join(config.exporters)}",
        f"Aggregation temporality: {config.aggregation_temporality}",
    ]

    return {
        "stage": MetricStage.OPTIMIZE.value,
        "pipeline_config": config.model_dump(),
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def optimize_cardinality(
    state: dict[str, Any],
    toolkit: OTelMetricsPipelineToolkit,
) -> dict[str, Any]:
    """Analyze and optimize metric cardinality for each service."""
    logger.info("otel_metrics_pipeline.node.optimize_cardinality")

    raw_endpoints = state.get("endpoints", [])
    endpoints = [MetricEndpoint(**ep) if isinstance(ep, dict) else ep for ep in raw_endpoints]

    reports: list[CardinalityReport] = []
    reasoning: list[str] = []

    services_seen: set[str] = set()
    for ep in endpoints:
        if ep.service in services_seen:
            continue
        services_seen.add(ep.service)

        report = toolkit.analyze_cardinality(ep.service)
        reports.append(report)
        reasoning.append(
            f"Cardinality for {report.service}: {report.total_series} series, "
            f"{len(report.high_cardinality_metrics)} high-cardinality metrics, "
            f"est. {report.estimated_savings_pct:.1f}% savings if drops applied"
        )

    return {
        "stage": MetricStage.VALIDATE.value,
        "cardinality_reports": [r.model_dump() for r in reports],
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }


async def validate_coverage(
    state: dict[str, Any],
    toolkit: OTelMetricsPipelineToolkit,
) -> dict[str, Any]:
    """Validate golden signals coverage and generate final pipeline YAML."""
    logger.info("otel_metrics_pipeline.node.validate_coverage")
    namespace = state.get("target_namespace", "default")

    golden = toolkit.check_golden_signals(namespace)

    reasoning: list[str] = [
        "Golden signals coverage:",
    ]
    for signal, covered in golden.items():
        status = "covered" if covered else "MISSING"
        reasoning.append(f"  {signal}: {status}")

    missing = [s for s, c in golden.items() if not c]
    if missing:
        reasoning.append(f"WARNING: Missing golden signals: {', '.join(missing)}")
    else:
        reasoning.append("All four golden signals are covered.")

    # Generate pipeline YAML
    raw_config = state.get("pipeline_config")
    if raw_config:
        config = MetricPipelineConfig(**raw_config) if isinstance(raw_config, dict) else raw_config
        raw_endpoints = state.get("endpoints", [])
        endpoints = [MetricEndpoint(**ep) if isinstance(ep, dict) else ep for ep in raw_endpoints]
        pipeline_yaml = toolkit.generate_metrics_pipeline_yaml(config, endpoints)
        reasoning.append(f"Generated OTel Collector YAML ({len(pipeline_yaml)} chars)")

    return {
        "golden_signals_coverage": golden,
        "reasoning_chain": state.get("reasoning_chain", []) + reasoning,
    }
