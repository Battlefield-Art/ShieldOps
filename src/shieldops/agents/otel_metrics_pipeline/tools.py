"""OTel Metrics Pipeline Agent — Tool functions for metrics pipeline management."""

from __future__ import annotations

from typing import Any

import structlog
import yaml

from .models import (
    CardinalityReport,
    MetricEndpoint,
    MetricPipelineConfig,
    MetricSource,
)

logger = structlog.get_logger()


class OTelMetricsPipelineToolkit:
    """Tools for OpenTelemetry metrics pipeline configuration and optimization."""

    def __init__(
        self,
        k8s_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._k8s_client = k8s_client
        self._repository = repository

    async def discover_metric_endpoints(
        self,
        namespace: str,
    ) -> list[MetricEndpoint]:
        """Find Prometheus endpoints, OTLP sources, and other metric emitters.

        In production this queries the Kubernetes API for ServiceMonitors,
        PodMonitors, and pod annotations. Returns simulated data when no
        backend is connected.
        """
        logger.info(
            "otel_metrics_pipeline.discover_metric_endpoints",
            namespace=namespace,
        )

        if self._k8s_client is not None:
            try:
                sources = await self._k8s_client.list_metric_endpoints(
                    namespace=namespace,
                )
                return [
                    MetricEndpoint(
                        service=s["service"],
                        source=MetricSource(s.get("source", "prometheus")),
                        endpoint=s.get("endpoint", ""),
                        scrape_interval_s=s.get("scrape_interval_s", 15),
                        metric_count=s.get("metric_count", 0),
                    )
                    for s in sources
                ]
            except Exception:
                logger.exception("otel_metrics_pipeline.discover_metric_endpoints.error")
                return [
                    MetricEndpoint(service="unknown", metric_count=0),
                ]

        # Simulated endpoints for demo / testing
        return [
            MetricEndpoint(
                service="api-gateway",
                source=MetricSource.PROMETHEUS,
                endpoint="http://api-gateway:9090/metrics",
                scrape_interval_s=15,
                metric_count=320,
            ),
            MetricEndpoint(
                service="payment-service",
                source=MetricSource.OTLP,
                endpoint="payment-service:4317",
                scrape_interval_s=10,
                metric_count=185,
            ),
            MetricEndpoint(
                service="cache-service",
                source=MetricSource.STATSD,
                endpoint="cache-service:8125",
                scrape_interval_s=10,
                metric_count=45,
            ),
            MetricEndpoint(
                service="node-exporter",
                source=MetricSource.HOSTMETRICS,
                endpoint="localhost:9100/metrics",
                scrape_interval_s=30,
                metric_count=520,
            ),
        ]

    def configure_pipeline(
        self,
        endpoints: list[MetricEndpoint],
    ) -> MetricPipelineConfig:
        """Build an optimal metrics pipeline config based on discovered endpoints.

        Selects receivers, processors, and exporters based on the source types
        present in the endpoints.
        """
        logger.info(
            "otel_metrics_pipeline.configure_pipeline",
            endpoint_count=len(endpoints),
        )

        sources = {ep.source for ep in endpoints}
        receivers: list[str] = []
        if MetricSource.PROMETHEUS in sources:
            receivers.append("prometheus")
        if MetricSource.OTLP in sources:
            receivers.append("otlp")
        if MetricSource.STATSD in sources:
            receivers.append("statsd")
        if MetricSource.HOSTMETRICS in sources:
            receivers.append("hostmetrics")
        if MetricSource.KUBELETSTATS in sources:
            receivers.append("kubeletstats")

        # Always include core processors
        processors = [
            "memory_limiter",
            "batch",
            "metricstransform",
            "filter",
        ]

        # Choose exporters
        exporters: list[str] = []
        if MetricSource.PROMETHEUS in sources:
            exporters.append("prometheusremotewrite")
        exporters.append("otlp")

        # Determine temporality: delta if StatsD is present, otherwise cumulative
        temporality = "delta" if MetricSource.STATSD in sources else "cumulative"

        return MetricPipelineConfig(
            receivers=receivers,
            processors=processors,
            exporters=exporters,
            aggregation_temporality=temporality,
        )

    def analyze_cardinality(self, service: str) -> CardinalityReport:
        """Detect high-cardinality metrics for a service.

        In production this queries the metrics backend for series counts.
        Returns simulated analysis for demo / testing.
        """
        logger.info(
            "otel_metrics_pipeline.analyze_cardinality",
            service=service,
        )

        # Simulated cardinality data per service pattern
        cardinality_profiles: dict[str, dict[str, Any]] = {
            "api-gateway": {
                "total_series": 45000,
                "high_cardinality_metrics": [
                    "http_server_duration_bucket",
                    "http_server_request_size_bucket",
                ],
                "recommended_drops": [
                    "go_memstats_alloc_bytes_total",
                    "go_gc_duration_seconds",
                ],
                "estimated_savings_pct": 22.5,
            },
            "payment-service": {
                "total_series": 12000,
                "high_cardinality_metrics": [
                    "payment_transaction_duration_bucket",
                ],
                "recommended_drops": [
                    "process_cpu_seconds_total",
                ],
                "estimated_savings_pct": 8.0,
            },
        }

        profile = cardinality_profiles.get(service, {})
        return CardinalityReport(
            service=service,
            total_series=profile.get("total_series", 5000),
            high_cardinality_metrics=profile.get("high_cardinality_metrics", []),
            recommended_drops=profile.get("recommended_drops", []),
            estimated_savings_pct=profile.get("estimated_savings_pct", 5.0),
        )

    def check_golden_signals(self, namespace: str) -> dict[str, bool]:
        """Verify coverage of the four golden signals: latency, traffic, errors, saturation.

        Returns a dict mapping each signal to a boolean indicating whether the
        pipeline has metrics covering that signal.
        """
        logger.info(
            "otel_metrics_pipeline.check_golden_signals",
            namespace=namespace,
        )

        # Simulated golden signals check
        return {
            "latency": True,
            "traffic": True,
            "errors": True,
            "saturation": True,
        }

    def generate_metrics_pipeline_yaml(
        self,
        config: MetricPipelineConfig,
        endpoints: list[MetricEndpoint] | None = None,
    ) -> str:
        """Generate OTel Collector YAML for a metrics pipeline.

        Produces a valid collector configuration with receivers, processors,
        exporters, and service pipeline sections.
        """
        logger.info(
            "otel_metrics_pipeline.generate_yaml",
            receivers=config.receivers,
            exporters=config.exporters,
        )

        # Build receivers section
        receivers_cfg: dict[str, Any] = {}
        ep_lookup: dict[str, MetricEndpoint] = {}
        if endpoints:
            for ep in endpoints:
                ep_lookup[ep.source.value] = ep

        if "prometheus" in config.receivers:
            prom_ep = ep_lookup.get("prometheus")
            scrape_interval = f"{prom_ep.scrape_interval_s}s" if prom_ep else "15s"
            targets: list[str] = []
            if endpoints:
                for ep in endpoints:
                    if ep.source == MetricSource.PROMETHEUS:
                        targets.append(ep.endpoint.replace("http://", ""))
            if not targets:
                targets = ["localhost:9090"]
            receivers_cfg["prometheus"] = {
                "config": {
                    "scrape_configs": [
                        {
                            "job_name": "otel-metrics-pipeline",
                            "scrape_interval": scrape_interval,
                            "static_configs": [{"targets": targets}],
                        }
                    ]
                }
            }

        if "otlp" in config.receivers:
            receivers_cfg["otlp"] = {
                "protocols": {
                    "grpc": {"endpoint": "0.0.0.0:4317"},
                    "http": {"endpoint": "0.0.0.0:4318"},
                }
            }

        if "statsd" in config.receivers:
            receivers_cfg["statsd"] = {
                "endpoint": "0.0.0.0:8125",
                "aggregation_interval": "60s",
            }

        if "hostmetrics" in config.receivers:
            receivers_cfg["hostmetrics"] = {
                "collection_interval": "30s",
                "scrapers": {
                    "cpu": {},
                    "memory": {},
                    "disk": {},
                    "network": {},
                },
            }

        if "kubeletstats" in config.receivers:
            receivers_cfg["kubeletstats"] = {
                "collection_interval": "30s",
                "auth_type": "serviceAccount",
                "endpoint": "https://${env:K8S_NODE_IP}:10250",
            }

        # Build processors section
        processors_cfg: dict[str, Any] = {}
        if "memory_limiter" in config.processors:
            processors_cfg["memory_limiter"] = {
                "check_interval": "5s",
                "limit_mib": 512,
                "spike_limit_mib": 128,
            }
        if "batch" in config.processors:
            processors_cfg["batch"] = {
                "send_batch_size": 1024,
                "timeout": "10s",
            }
        if "metricstransform" in config.processors:
            processors_cfg["metricstransform"] = {
                "transforms": [
                    {
                        "include": ".*",
                        "match_type": "regexp",
                        "action": "update",
                        "operations": [
                            {
                                "action": "add_label",
                                "new_label": "cluster",
                                "new_value": "${env:CLUSTER_NAME}",
                            }
                        ],
                    }
                ]
            }
        if "filter" in config.processors:
            processors_cfg["filter"] = {
                "metrics": {
                    "exclude": {
                        "match_type": "regexp",
                        "metric_names": [
                            "go_memstats_.*",
                            "go_gc_.*",
                            "process_.*",
                        ],
                    }
                }
            }

        # Build exporters section
        exporters_cfg: dict[str, Any] = {}
        if "prometheusremotewrite" in config.exporters:
            exporters_cfg["prometheusremotewrite"] = {
                "endpoint": "http://prometheus:9090/api/v1/write",
                "resource_to_telemetry_conversion": {"enabled": True},
            }
        if "otlp" in config.exporters:
            exporters_cfg["otlp"] = {
                "endpoint": "otel-backend:4317",
                "tls": {"insecure": False},
            }

        # Build service section
        collector_config: dict[str, Any] = {
            "receivers": receivers_cfg,
            "processors": processors_cfg,
            "exporters": exporters_cfg,
            "service": {
                "pipelines": {
                    "metrics": {
                        "receivers": config.receivers,
                        "processors": config.processors,
                        "exporters": config.exporters,
                    }
                }
            },
        }

        return yaml.dump(
            collector_config,
            default_flow_style=False,
            sort_keys=False,
        )
