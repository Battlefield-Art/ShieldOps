"""OTel Logs Pipeline Agent — Tool functions for logs pipeline management."""

from __future__ import annotations

from typing import Any

import structlog
import yaml

from .models import (
    LogEndpoint,
    LogFormat,
    LogParsingResult,
    LogPipelineConfig,
    LogSource,
)

logger = structlog.get_logger()


class OTelLogsPipelineToolkit:
    """Tools for OpenTelemetry logs pipeline configuration and management."""

    def __init__(
        self,
        k8s_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._k8s_client = k8s_client
        self._repository = repository

    async def discover_log_sources(
        self,
        namespace: str,
    ) -> list[LogEndpoint]:
        """Find log sources: filelog paths, syslog endpoints, OTLP, Kafka topics.

        In production this queries the Kubernetes API for pod log paths,
        syslog configurations, and Kafka topic metadata. Returns simulated
        data when no backend is connected.
        """
        logger.info(
            "otel_logs_pipeline.discover_log_sources",
            namespace=namespace,
        )

        if self._k8s_client is not None:
            try:
                sources = await self._k8s_client.list_log_sources(
                    namespace=namespace,
                )
                return [
                    LogEndpoint(
                        service=s["service"],
                        source=LogSource(s.get("source", "filelog")),
                        path_or_endpoint=s.get("path_or_endpoint", ""),
                        format=LogFormat(s.get("format", "json")),
                        volume_per_min=s.get("volume_per_min", 0),
                        parse_rules=s.get("parse_rules", []),
                    )
                    for s in sources
                ]
            except Exception:
                logger.exception("otel_logs_pipeline.discover_log_sources.error")
                return [
                    LogEndpoint(service="unknown", volume_per_min=0),
                ]

        # Simulated endpoints for demo / testing
        return [
            LogEndpoint(
                service="api-gateway",
                source=LogSource.FILELOG,
                path_or_endpoint="/var/log/pods/default_api-gateway-*/api-gateway/*.log",
                format=LogFormat.JSON,
                volume_per_min=2400,
                parse_rules=["json_parser"],
            ),
            LogEndpoint(
                service="auth-service",
                source=LogSource.SYSLOG,
                path_or_endpoint="0.0.0.0:514",
                format=LogFormat.SYSLOG_RFC5424,
                volume_per_min=800,
                parse_rules=["syslog_parser"],
            ),
            LogEndpoint(
                service="payment-service",
                source=LogSource.OTLP,
                path_or_endpoint="payment-service:4317",
                format=LogFormat.JSON,
                volume_per_min=1200,
                parse_rules=[],
            ),
            LogEndpoint(
                service="event-processor",
                source=LogSource.KAFKA,
                path_or_endpoint="kafka:9092/logs-topic",
                format=LogFormat.JSON,
                volume_per_min=5000,
                parse_rules=["json_parser"],
            ),
            LogEndpoint(
                service="node-agent",
                source=LogSource.JOURNALD,
                path_or_endpoint="/run/log/journal",
                format=LogFormat.TEXT,
                volume_per_min=600,
                parse_rules=["regex_parser"],
            ),
        ]

    def configure_log_pipeline(
        self,
        endpoints: list[LogEndpoint],
    ) -> LogPipelineConfig:
        """Build an optimal logs pipeline config based on discovered endpoints.

        Selects receivers, processors, and exporters based on the source types
        present in the endpoints.
        """
        logger.info(
            "otel_logs_pipeline.configure_log_pipeline",
            endpoint_count=len(endpoints),
        )

        sources = {ep.source for ep in endpoints}
        receivers: list[str] = []
        if LogSource.FILELOG in sources:
            receivers.append("filelog")
        if LogSource.SYSLOG in sources:
            receivers.append("syslog")
        if LogSource.OTLP in sources:
            receivers.append("otlp")
        if LogSource.KAFKA in sources:
            receivers.append("kafka")
        if LogSource.JOURNALD in sources:
            receivers.append("journald")
        if LogSource.WINDOWSEVENTLOG in sources:
            receivers.append("windowseventlog")

        # Always include core processors
        processors = [
            "memory_limiter",
            "batch",
            "attributes",
            "resource",
            "transform",
            "filter",
        ]

        # Choose exporters
        exporters: list[str] = ["otlp"]
        if LogSource.SYSLOG in sources:
            exporters.append("loki")
        if LogSource.FILELOG in sources or LogSource.KAFKA in sources:
            exporters.append("elasticsearch")

        # Resource attributes for enrichment
        resource_attributes: dict[str, str] = {
            "cluster": "${env:CLUSTER_NAME}",
            "environment": "${env:ENVIRONMENT}",
        }

        return LogPipelineConfig(
            receivers=receivers,
            processors=processors,
            exporters=exporters,
            resource_attributes=resource_attributes,
        )

    def test_log_parsing(
        self,
        service: str,
        sample_logs: list[str] | None = None,
    ) -> LogParsingResult:
        """Test log parsing rules for a service.

        In production this sends sample logs through the collector's
        parsing pipeline and reports success/failure rates.
        Returns simulated results for demo / testing.
        """
        logger.info(
            "otel_logs_pipeline.test_log_parsing",
            service=service,
        )

        # Simulated parsing results per service
        parsing_profiles: dict[str, dict[str, Any]] = {
            "api-gateway": {
                "parsed_pct": 98.5,
                "failed_pct": 1.5,
                "sample_errors": [
                    "Line 4521: malformed JSON — unexpected EOF",
                ],
            },
            "auth-service": {
                "parsed_pct": 95.0,
                "failed_pct": 5.0,
                "sample_errors": [
                    "Line 128: syslog priority missing",
                    "Line 892: timestamp parse failed",
                ],
            },
            "payment-service": {
                "parsed_pct": 99.8,
                "failed_pct": 0.2,
                "sample_errors": [],
            },
            "event-processor": {
                "parsed_pct": 97.2,
                "failed_pct": 2.8,
                "sample_errors": [
                    "Line 3001: nested JSON depth exceeded",
                ],
            },
            "node-agent": {
                "parsed_pct": 88.0,
                "failed_pct": 12.0,
                "sample_errors": [
                    "Line 55: regex did not match — multiline stack trace",
                    "Line 201: unknown severity level 'NOTICE'",
                ],
            },
        }

        profile = parsing_profiles.get(service, {})
        return LogParsingResult(
            service=service,
            parsed_pct=profile.get("parsed_pct", 90.0),
            failed_pct=profile.get("failed_pct", 10.0),
            sample_errors=profile.get("sample_errors", ["Unknown format"]),
        )

    def check_trace_correlation(self, namespace: str) -> dict[str, Any]:
        """Verify logs have trace_id/span_id for trace-log correlation.

        Returns correlation statistics per service including percentage
        of logs with valid trace context.
        """
        logger.info(
            "otel_logs_pipeline.check_trace_correlation",
            namespace=namespace,
        )

        # Simulated trace correlation data
        return {
            "namespace": namespace,
            "overall_correlation_rate": 0.82,
            "services": {
                "api-gateway": {"correlation_rate": 0.95, "has_trace_id": True},
                "auth-service": {"correlation_rate": 0.60, "has_trace_id": True},
                "payment-service": {"correlation_rate": 0.98, "has_trace_id": True},
                "event-processor": {"correlation_rate": 0.75, "has_trace_id": True},
                "node-agent": {"correlation_rate": 0.0, "has_trace_id": False},
            },
        }

    def generate_logs_pipeline_yaml(
        self,
        config: LogPipelineConfig,
        endpoints: list[LogEndpoint] | None = None,
    ) -> str:
        """Generate OTel Collector YAML for a logs pipeline.

        Produces a valid collector configuration with receivers, processors,
        exporters, and service pipeline sections.
        """
        logger.info(
            "otel_logs_pipeline.generate_yaml",
            receivers=config.receivers,
            exporters=config.exporters,
        )

        # Build receivers section
        receivers_cfg: dict[str, Any] = {}

        if "filelog" in config.receivers:
            include_paths: list[str] = []
            if endpoints:
                for ep in endpoints:
                    if ep.source == LogSource.FILELOG:
                        include_paths.append(ep.path_or_endpoint)
            if not include_paths:
                include_paths = ["/var/log/pods/*/*/*.log"]
            receivers_cfg["filelog"] = {
                "include": include_paths,
                "include_file_name": False,
                "include_file_path": True,
                "operators": [
                    {
                        "type": "json_parser",
                        "timestamp": {
                            "parse_from": "attributes.time",
                            "layout": "%Y-%m-%dT%H:%M:%S.%LZ",
                        },
                    },
                ],
            }

        if "syslog" in config.receivers:
            receivers_cfg["syslog"] = {
                "protocol": "rfc5424",
                "tcp": {"listen_address": "0.0.0.0:514"},
                "udp": {"listen_address": "0.0.0.0:514"},
            }

        if "otlp" in config.receivers:
            receivers_cfg["otlp"] = {
                "protocols": {
                    "grpc": {"endpoint": "0.0.0.0:4317"},
                    "http": {"endpoint": "0.0.0.0:4318"},
                },
            }

        if "kafka" in config.receivers:
            receivers_cfg["kafka"] = {
                "brokers": ["kafka:9092"],
                "topic": "logs-topic",
                "encoding": "otlp_proto",
                "group_id": "otel-collector-logs",
            }

        if "journald" in config.receivers:
            receivers_cfg["journald"] = {
                "directory": "/run/log/journal",
                "units": ["kubelet", "docker", "containerd"],
            }

        if "windowseventlog" in config.receivers:
            receivers_cfg["windowseventlog"] = {
                "channel": "Application",
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
                "timeout": "5s",
            }
        if "attributes" in config.processors:
            processors_cfg["attributes"] = {
                "actions": [
                    {
                        "key": "log.source",
                        "action": "insert",
                        "value": "otel-collector",
                    },
                ],
            }
        if "resource" in config.processors:
            resource_attrs = []
            for k, v in config.resource_attributes.items():
                resource_attrs.append({"key": k, "action": "upsert", "value": v})
            processors_cfg["resource"] = {"attributes": resource_attrs}
        if "transform" in config.processors:
            processors_cfg["transform"] = {
                "log_statements": [
                    {
                        "context": "log",
                        "statements": [
                            'set(severity_text, "INFO") where severity_number == 0',
                        ],
                    },
                ],
            }
        if "filter" in config.processors:
            processors_cfg["filter"] = {
                "logs": {
                    "exclude": {
                        "match_type": "regexp",
                        "bodies": [
                            "^\\s*$",
                            "health.check",
                        ],
                    },
                },
            }

        # Build exporters section
        exporters_cfg: dict[str, Any] = {}
        if "otlp" in config.exporters:
            exporters_cfg["otlp"] = {
                "endpoint": "otel-backend:4317",
                "tls": {"insecure": False},
            }
        if "loki" in config.exporters:
            exporters_cfg["loki"] = {
                "endpoint": "http://loki:3100/loki/api/v1/push",
                "labels": {
                    "attributes": {"severity": "severity_text"},
                    "resource": {"service.name": "service_name"},
                },
            }
        if "elasticsearch" in config.exporters:
            exporters_cfg["elasticsearch"] = {
                "endpoints": ["https://elasticsearch:9200"],
                "logs_index": "otel-logs",
                "tls": {"insecure_skip_verify": False},
            }

        # Build service section
        collector_config: dict[str, Any] = {
            "receivers": receivers_cfg,
            "processors": processors_cfg,
            "exporters": exporters_cfg,
            "service": {
                "pipelines": {
                    "logs": {
                        "receivers": config.receivers,
                        "processors": config.processors,
                        "exporters": config.exporters,
                    },
                },
            },
        }

        return yaml.dump(
            collector_config,
            default_flow_style=False,
            sort_keys=False,
        )
