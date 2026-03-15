"""OTel Pipeline Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PipelineStage(StrEnum):
    DISCOVER = "discover"
    CONFIGURE = "configure"
    VALIDATE = "validate"
    DEPLOY = "deploy"
    MONITOR = "monitor"


class CollectorMode(StrEnum):
    DAEMONSET = "daemonset"
    SIDECAR = "sidecar"
    GATEWAY = "gateway"
    STANDALONE = "standalone"


class ExporterTarget(StrEnum):
    SHIELDOPS = "shieldops"
    SPLUNK_HEC = "splunk_hec"
    OTLP_HTTP = "otlp_http"
    OTLP_GRPC = "otlp_grpc"
    PROMETHEUS = "prometheus"
    DATADOG = "datadog"


class PipelineComponent(BaseModel):
    name: str = ""
    component_type: str = ""  # receiver, processor, exporter
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class CollectorConfig(BaseModel):
    collector_id: str = ""
    mode: CollectorMode = CollectorMode.DAEMONSET
    receivers: list[PipelineComponent] = Field(default_factory=list)
    processors: list[PipelineComponent] = Field(default_factory=list)
    exporters: list[PipelineComponent] = Field(default_factory=list)
    resource_limits: dict[str, str] = Field(default_factory=dict)


class InstrumentationTarget(BaseModel):
    service_name: str = ""
    language: str = "python"
    namespace: str = "default"
    auto_instrument: bool = True
    libraries: list[str] = Field(default_factory=list)


class PipelineHealthMetric(BaseModel):
    collector_id: str = ""
    dropped_spans: int = 0
    dropped_metrics: int = 0
    dropped_logs: int = 0
    queue_depth: int = 0
    export_latency_ms: float = 0.0
    healthy: bool = True


class OTelPipelineState(BaseModel):
    """Main state for the OTel Pipeline agent graph."""

    request_id: str = ""
    stage: PipelineStage = PipelineStage.DISCOVER
    cluster_name: str = ""
    namespace: str = "default"

    # Discovery
    discovered_services: list[dict[str, Any]] = Field(default_factory=list)
    existing_collectors: list[CollectorConfig] = Field(default_factory=list)

    # Configuration
    target_config: CollectorConfig | None = None
    instrumentation_targets: list[InstrumentationTarget] = Field(default_factory=list)
    kafka_topics: list[str] = Field(default_factory=list)
    exporter_targets: list[ExporterTarget] = Field(default_factory=list)

    # Validation
    config_valid: bool = False
    validation_errors: list[str] = Field(default_factory=list)

    # Health
    health_metrics: list[PipelineHealthMetric] = Field(default_factory=list)
    pipeline_score: float = 0.0

    # Output
    recommendations: list[str] = Field(default_factory=list)
    actions_taken: list[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    reasoning_chain: list[str] = Field(default_factory=list)
