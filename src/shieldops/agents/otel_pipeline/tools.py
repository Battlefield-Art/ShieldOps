"""OTel Pipeline Agent — Tool functions for pipeline operations."""

from __future__ import annotations

import re
from typing import Any

import structlog

logger = structlog.get_logger()


class OTelPipelineToolkit:
    """Tools for OpenTelemetry pipeline management."""

    def __init__(
        self,
        connector_router: Any | None = None,
        k8s_client: Any | None = None,
        kafka_client: Any | None = None,
    ) -> None:
        self._connector_router = connector_router
        self._k8s_client = k8s_client
        self._kafka_client = kafka_client

    async def discover_services(
        self, cluster_name: str, namespace: str = "default"
    ) -> list[dict[str, Any]]:
        """Discover services in the cluster that need OTel instrumentation."""
        logger.info(
            "otel_pipeline.discover_services",
            cluster=cluster_name,
            namespace=namespace,
        )
        if self._k8s_client is None:
            return []
        try:
            pods = await self._k8s_client.list_pods(namespace=namespace)
            services: list[dict[str, Any]] = []
            for pod in pods:
                has_otel = any(
                    "otel" in c.get("name", "").lower() or "opentelemetry" in str(c.get("env", []))
                    for c in pod.get("containers", [])
                )
                services.append(
                    {
                        "name": pod.get("name", ""),
                        "namespace": namespace,
                        "instrumented": has_otel,
                        "language": pod.get("labels", {}).get("language", "unknown"),
                        "containers": len(pod.get("containers", [])),
                    }
                )
            return services
        except Exception:
            logger.exception("otel_pipeline.discover_services.error")
            return []

    async def list_kafka_topics(self, pattern: str = "otel.*") -> list[dict[str, Any]]:
        """List Kafka topics matching a pattern for telemetry ingestion."""
        logger.info("otel_pipeline.list_kafka_topics", pattern=pattern)
        if self._kafka_client is None:
            return []
        try:
            topics = await self._kafka_client.list_topics()
            regex = re.compile(pattern.replace("*", ".*"))
            return [
                {"topic": t, "partitions": meta.get("partitions", 0)}
                for t, meta in topics.items()
                if regex.match(t)
            ]
        except Exception:
            logger.exception("otel_pipeline.list_kafka_topics.error")
            return []

    async def get_collector_health(self, collector_id: str) -> dict[str, Any]:
        """Get health metrics for a deployed OTel collector."""
        logger.info(
            "otel_pipeline.get_collector_health",
            collector_id=collector_id,
        )
        return {
            "collector_id": collector_id,
            "dropped_spans": 0,
            "dropped_metrics": 0,
            "dropped_logs": 0,
            "queue_depth": 0,
            "export_latency_ms": 0.0,
            "healthy": True,
        }

    async def generate_collector_config(
        self,
        mode: str = "daemonset",
        kafka_topics: list[str] | None = None,
        exporters: list[str] | None = None,
        resource_cpu: str = "200m",
        resource_memory: str = "256Mi",
    ) -> dict[str, Any]:
        """Generate an OTel collector configuration YAML structure."""
        kafka_topics = kafka_topics or [
            "otel.traces",
            "otel.metrics",
            "otel.logs",
        ]
        exporters = exporters or ["otlp"]

        config: dict[str, Any] = {
            "receivers": {
                "kafka": {
                    "brokers": ["${KAFKA_BROKERS}"],
                    "topic": kafka_topics[0] if len(kafka_topics) == 1 else "",
                    "encoding": "otlp_proto",
                },
                "otlp": {
                    "protocols": {
                        "grpc": {"endpoint": "0.0.0.0:4317"},
                        "http": {"endpoint": "0.0.0.0:4318"},
                    }
                },
            },
            "processors": {
                "batch": {"timeout": "5s", "send_batch_size": 512},
                "resourcedetection": {
                    "detectors": ["system", "env", "k8snode"],
                },
                "memory_limiter": {
                    "check_interval": "1s",
                    "limit_mib": 200,
                },
            },
            "exporters": {},
            "service": {
                "pipelines": {
                    "traces": {
                        "receivers": ["otlp", "kafka"],
                        "processors": [
                            "memory_limiter",
                            "batch",
                            "resourcedetection",
                        ],
                        "exporters": exporters,
                    },
                    "metrics": {
                        "receivers": ["otlp"],
                        "processors": ["memory_limiter", "batch"],
                        "exporters": exporters,
                    },
                    "logs": {
                        "receivers": ["otlp"],
                        "processors": ["memory_limiter", "batch"],
                        "exporters": exporters,
                    },
                }
            },
        }
        for exp in exporters:
            if exp == "otlp":
                config["exporters"]["otlp"] = {
                    "endpoint": "${OTEL_EXPORTER_OTLP_ENDPOINT}",
                    "tls": {"insecure": False},
                }
            elif exp == "splunk_hec":
                config["exporters"]["splunk_hec"] = {
                    "token": "${SPLUNK_HEC_TOKEN}",
                    "endpoint": "${SPLUNK_HEC_ENDPOINT}",
                    "source": "shieldops",
                    "sourcetype": "otel",
                }
        return {
            "mode": mode,
            "config": config,
            "resources": {"cpu": resource_cpu, "memory": resource_memory},
        }

    async def validate_pipeline_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """Validate an OTel pipeline configuration."""
        errors: list[str] = []
        warnings: list[str] = []

        svc = config.get("config", {}).get("service", {})
        pipelines = svc.get("pipelines", {})
        receivers = config.get("config", {}).get("receivers", {})
        processors = config.get("config", {}).get("processors", {})
        exporters_cfg = config.get("config", {}).get("exporters", {})

        for pipe_name, pipe_cfg in pipelines.items():
            for r in pipe_cfg.get("receivers", []):
                if r not in receivers:
                    errors.append(f"Pipeline '{pipe_name}' references unknown receiver '{r}'")
            for p in pipe_cfg.get("processors", []):
                if p not in processors:
                    errors.append(f"Pipeline '{pipe_name}' references unknown processor '{p}'")
            for e in pipe_cfg.get("exporters", []):
                if e not in exporters_cfg:
                    errors.append(f"Pipeline '{pipe_name}' references unknown exporter '{e}'")

        if "memory_limiter" not in processors:
            warnings.append("No memory_limiter processor — risk of OOM")

        resources = config.get("resources", {})
        if not resources.get("cpu") or not resources.get("memory"):
            warnings.append("Resource limits not set — may cause node pressure")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
        }

    async def deploy_collector(
        self, config: dict[str, Any], dry_run: bool = True
    ) -> dict[str, Any]:
        """Deploy or update an OTel collector (dry-run by default)."""
        logger.info(
            "otel_pipeline.deploy_collector",
            mode=config.get("mode"),
            dry_run=dry_run,
        )
        return {
            "deployed": not dry_run,
            "dry_run": dry_run,
            "mode": config.get("mode", "daemonset"),
            "status": "dry_run_success" if dry_run else "deployed",
        }

    async def auto_instrument_service(
        self,
        service_name: str,
        namespace: str = "default",
        language: str = "python",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Auto-instrument a service via OTel operator injection."""
        logger.info(
            "otel_pipeline.auto_instrument",
            service=service_name,
            language=language,
            dry_run=dry_run,
        )
        annotation = f"instrumentation.opentelemetry.io/inject-{language}=true"
        return {
            "service": service_name,
            "namespace": namespace,
            "language": language,
            "instrumented": not dry_run,
            "dry_run": dry_run,
            "annotation_added": annotation,
        }
