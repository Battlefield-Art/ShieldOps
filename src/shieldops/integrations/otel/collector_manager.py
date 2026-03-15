"""OpenTelemetry collector lifecycle manager for ShieldOps.

Manages collector deployment, configuration, scaling, and health monitoring.
Inspired by splunk-otel-collector-chart patterns.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class DeploymentMode(StrEnum):
    DAEMONSET = "daemonset"
    DEPLOYMENT = "deployment"
    SIDECAR = "sidecar"
    STANDALONE = "standalone"


class CollectorStatus(StrEnum):
    RUNNING = "running"
    DEGRADED = "degraded"
    STOPPED = "stopped"
    DEPLOYING = "deploying"
    SCALING = "scaling"


class CollectorSpec(BaseModel):
    """Specification for an OTel collector deployment."""

    name: str = ""
    namespace: str = "shieldops"
    mode: DeploymentMode = DeploymentMode.DAEMONSET
    image: str = "otel/opentelemetry-collector-contrib:latest"
    replicas: int = 1
    resource_cpu: str = "200m"
    resource_memory: str = "256Mi"
    resource_cpu_limit: str = "500m"
    resource_memory_limit: str = "512Mi"
    receivers: list[str] = Field(default_factory=lambda: ["otlp"])
    processors: list[str] = Field(
        default_factory=lambda: ["memory_limiter", "batch", "resourcedetection"]
    )
    exporters: list[str] = Field(default_factory=lambda: ["otlp"])
    config_override: dict[str, Any] = Field(default_factory=dict)


class CollectorInstance(BaseModel):
    """A running collector instance."""

    name: str = ""
    namespace: str = ""
    mode: DeploymentMode = DeploymentMode.DAEMONSET
    status: CollectorStatus = CollectorStatus.STOPPED
    replicas_desired: int = 0
    replicas_ready: int = 0
    uptime_seconds: float = 0.0
    last_health_check: float = 0.0


class CollectorManager:
    """Manages OpenTelemetry collector lifecycle."""

    def __init__(
        self,
        k8s_client: Any | None = None,
    ) -> None:
        self._k8s_client = k8s_client
        self._collectors: dict[str, CollectorInstance] = {}
        logger.info("collector_manager.init")

    async def deploy(
        self,
        spec: CollectorSpec,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Deploy a new OTel collector."""
        logger.info(
            "collector_manager.deploy",
            name=spec.name,
            mode=spec.mode.value,
            dry_run=dry_run,
        )
        config = self._generate_config(spec)

        if dry_run:
            return {
                "status": "dry_run",
                "name": spec.name,
                "mode": spec.mode.value,
                "config": config,
            }

        instance = CollectorInstance(
            name=spec.name,
            namespace=spec.namespace,
            mode=spec.mode,
            status=CollectorStatus.DEPLOYING,
            replicas_desired=spec.replicas,
        )
        self._collectors[spec.name] = instance

        if self._k8s_client:
            await self._k8s_client.apply_manifest(config)
            instance.status = CollectorStatus.RUNNING

        return {
            "status": "deployed",
            "name": spec.name,
            "mode": spec.mode.value,
        }

    async def scale(
        self,
        name: str,
        replicas: int,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Scale a collector deployment."""
        logger.info(
            "collector_manager.scale",
            name=name,
            replicas=replicas,
            dry_run=dry_run,
        )
        instance = self._collectors.get(name)
        if instance is None:
            return {"status": "not_found", "name": name}

        if not dry_run:
            instance.replicas_desired = replicas
            instance.status = CollectorStatus.SCALING

        return {
            "status": "dry_run" if dry_run else "scaling",
            "name": name,
            "replicas": replicas,
        }

    async def health_check(self, name: str) -> dict[str, Any]:
        """Check health of a collector."""
        instance = self._collectors.get(name)
        if instance is None:
            return {"status": "not_found", "name": name}

        return {
            "name": name,
            "status": instance.status.value,
            "replicas_desired": instance.replicas_desired,
            "replicas_ready": instance.replicas_ready,
            "healthy": instance.status == CollectorStatus.RUNNING,
        }

    async def list_collectors(self) -> list[dict[str, Any]]:
        """List all managed collectors."""
        return [
            {
                "name": inst.name,
                "namespace": inst.namespace,
                "mode": inst.mode.value,
                "status": inst.status.value,
            }
            for inst in self._collectors.values()
        ]

    def _generate_config(self, spec: CollectorSpec) -> dict[str, Any]:
        """Generate OTel collector YAML config from spec."""
        receivers_config: dict[str, Any] = {}
        for r in spec.receivers:
            if r == "otlp":
                receivers_config["otlp"] = {
                    "protocols": {
                        "grpc": {"endpoint": "0.0.0.0:4317"},
                        "http": {"endpoint": "0.0.0.0:4318"},
                    }
                }
            elif r == "kafka":
                receivers_config["kafka"] = {
                    "brokers": ["${KAFKA_BROKERS}"],
                    "encoding": "otlp_proto",
                }

        processors_config: dict[str, Any] = {}
        for p in spec.processors:
            if p == "batch":
                processors_config["batch"] = {
                    "timeout": "5s",
                    "send_batch_size": 512,
                }
            elif p == "memory_limiter":
                processors_config["memory_limiter"] = {
                    "check_interval": "1s",
                    "limit_mib": int(spec.resource_memory_limit.replace("Mi", ""))
                    if spec.resource_memory_limit.endswith("Mi")
                    else 512,
                }
            elif p == "resourcedetection":
                processors_config["resourcedetection"] = {
                    "detectors": ["system", "env"],
                }

        exporters_config: dict[str, Any] = {}
        for e in spec.exporters:
            if e == "otlp":
                exporters_config["otlp"] = {
                    "endpoint": "${OTEL_EXPORTER_OTLP_ENDPOINT}",
                }

        config: dict[str, Any] = {
            "apiVersion": "opentelemetry.io/v1beta1",
            "kind": "OpenTelemetryCollector",
            "metadata": {
                "name": spec.name,
                "namespace": spec.namespace,
            },
            "spec": {
                "mode": spec.mode.value,
                "replicas": spec.replicas,
                "image": spec.image,
                "resources": {
                    "requests": {
                        "cpu": spec.resource_cpu,
                        "memory": spec.resource_memory,
                    },
                    "limits": {
                        "cpu": spec.resource_cpu_limit,
                        "memory": spec.resource_memory_limit,
                    },
                },
                "config": {
                    "receivers": receivers_config,
                    "processors": processors_config,
                    "exporters": exporters_config,
                    "service": {
                        "pipelines": {
                            "traces": {
                                "receivers": spec.receivers,
                                "processors": spec.processors,
                                "exporters": spec.exporters,
                            },
                        },
                    },
                },
            },
        }

        if spec.config_override:
            config["spec"]["config"].update(spec.config_override)

        return config
