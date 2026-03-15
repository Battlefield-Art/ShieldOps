"""OTel Logs Pipeline Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class LogStage(StrEnum):
    DISCOVER = "discover"
    CONFIGURE = "configure"
    PARSE = "parse"
    VALIDATE = "validate"


class LogSource(StrEnum):
    FILELOG = "filelog"
    SYSLOG = "syslog"
    OTLP = "otlp"
    KAFKA = "kafka"
    JOURNALD = "journald"
    WINDOWSEVENTLOG = "windowseventlog"


class LogFormat(StrEnum):
    JSON = "json"
    TEXT = "text"
    REGEX = "regex"
    CSV = "csv"
    SYSLOG_RFC5424 = "syslog_rfc5424"


class LogEndpoint(BaseModel):
    """A discovered log source in the cluster."""

    service: str = ""
    source: LogSource = LogSource.FILELOG
    path_or_endpoint: str = ""
    format: LogFormat = LogFormat.JSON
    volume_per_min: int = 0
    parse_rules: list[str] = Field(default_factory=list)


class LogPipelineConfig(BaseModel):
    """Configuration for an OTel logs pipeline."""

    receivers: list[str] = Field(default_factory=list)
    processors: list[str] = Field(default_factory=list)
    exporters: list[str] = Field(default_factory=list)
    resource_attributes: dict[str, str] = Field(default_factory=dict)


class LogParsingResult(BaseModel):
    """Parsing test result for a service's logs."""

    service: str = ""
    parsed_pct: float = 0.0
    failed_pct: float = 0.0
    sample_errors: list[str] = Field(default_factory=list)


class OTelLogsPipelineState(BaseModel):
    """Main state for the OTel Logs Pipeline agent graph."""

    request_id: str = ""
    stage: LogStage = LogStage.DISCOVER
    endpoints: list[LogEndpoint] = Field(default_factory=list)
    pipeline_config: LogPipelineConfig | None = None
    parsing_results: list[LogParsingResult] = Field(default_factory=list)
    trace_correlation_rate: float = 0.0
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
