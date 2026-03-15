"""OTel Collector Manager Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CollectorAction(StrEnum):
    DEPLOY = "deploy"
    CONFIGURE = "configure"
    SCALE = "scale"
    HEALTH_CHECK = "health_check"
    ROLLBACK = "rollback"


class PipelineType(StrEnum):
    TRACES = "traces"
    METRICS = "metrics"
    LOGS = "logs"


class DeploymentMode(StrEnum):
    AGENT = "agent"
    GATEWAY = "gateway"
    SIDECAR = "sidecar"


class ReceiverConfig(BaseModel):
    """Configuration for an OTel Collector receiver."""

    name: str = ""
    type: str = ""
    protocol: str = ""
    endpoint: str = ""
    extra_config: dict[str, Any] = Field(default_factory=dict)


class ProcessorConfig(BaseModel):
    """Configuration for an OTel Collector processor."""

    name: str = ""
    type: str = ""
    config: dict[str, Any] = Field(default_factory=dict)


class ExporterConfig(BaseModel):
    """Configuration for an OTel Collector exporter."""

    name: str = ""
    type: str = ""
    endpoint: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    extra_config: dict[str, Any] = Field(default_factory=dict)


class PipelineConfig(BaseModel):
    """Configuration for a single OTel service pipeline."""

    name: str = ""
    type: PipelineType = PipelineType.TRACES
    receivers: list[str] = Field(default_factory=list)
    processors: list[str] = Field(default_factory=list)
    exporters: list[str] = Field(default_factory=list)


class CollectorConfig(BaseModel):
    """Full OTel Collector configuration."""

    receivers: list[ReceiverConfig] = Field(default_factory=list)
    processors: list[ProcessorConfig] = Field(default_factory=list)
    exporters: list[ExporterConfig] = Field(default_factory=list)
    pipelines: list[PipelineConfig] = Field(default_factory=list)
    extensions: list[str] = Field(default_factory=list)
    deployment_mode: DeploymentMode = DeploymentMode.AGENT


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0


class OTelCollectorManagerState(BaseModel):
    """Main state for the OTel Collector Manager agent graph."""

    request_id: str = ""
    action: CollectorAction = CollectorAction.DEPLOY
    collector_config: CollectorConfig | None = None
    target_namespace: str = "default"
    health_status: dict[str, Any] = Field(default_factory=dict)
    deployment_result: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
