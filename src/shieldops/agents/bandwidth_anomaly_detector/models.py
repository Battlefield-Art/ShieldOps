"""Bandwidth Anomaly Detector Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DetectionStage(StrEnum):
    COLLECT_SAMPLES = "collect_samples"
    BUILD_BASELINES = "build_baselines"
    DETECT_ANOMALIES = "detect_anomalies"
    CLASSIFY_TRAFFIC = "classify_traffic"
    ALERT = "alert"
    REPORT = "report"


class AnomalyCategory(StrEnum):
    TRAFFIC_SPIKE = "traffic_spike"
    OFF_HOURS_TRANSFER = "off_hours_transfer"
    LARGE_EGRESS = "large_egress"
    CRYPTO_MINING = "crypto_mining"
    TORRENT_ACTIVITY = "torrent_activity"
    SHADOW_IT = "shadow_it"
    DGA_TRAFFIC = "dga_traffic"
    BEACONING = "beaconing"


class TrafficDirection(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    LATERAL = "lateral"
    UNKNOWN = "unknown"


class BandwidthSample(BaseModel):
    """A single bandwidth measurement sample."""

    source_ip: str = ""
    dest_ip: str = ""
    direction: TrafficDirection = TrafficDirection.UNKNOWN
    bytes_transferred: int = 0
    packets: int = 0
    protocol: str = ""
    port: int = 0
    timestamp: datetime | None = None
    interface: str = ""
    labels: dict[str, str] = Field(default_factory=dict)


class BaselineProfile(BaseModel):
    """Bandwidth baseline for a host or subnet."""

    entity: str = ""
    direction: TrafficDirection = TrafficDirection.OUTBOUND
    avg_bytes_per_hour: float = 0.0
    stddev_bytes: float = 0.0
    peak_bytes_per_hour: float = 0.0
    active_hours: list[int] = Field(default_factory=list)
    sample_count: int = 0
    last_updated: datetime | None = None


class AnomalyAlert(BaseModel):
    """An alert raised for a detected bandwidth anomaly."""

    alert_id: str = ""
    entity: str = ""
    category: AnomalyCategory = AnomalyCategory.TRAFFIC_SPIKE
    direction: TrafficDirection = TrafficDirection.OUTBOUND
    current_bytes: int = 0
    baseline_bytes: float = 0.0
    deviation_sigma: float = 0.0
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    severity: str = "medium"
    description: str = ""
    detected_at: datetime | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class BandwidthAnomalyDetectorState(BaseModel):
    """Main state for the Bandwidth Anomaly Detector agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: DetectionStage = DetectionStage.COLLECT_SAMPLES

    # Collected samples
    samples: list[dict[str, Any]] = Field(default_factory=list)

    # Baselines
    baselines: list[dict[str, Any]] = Field(default_factory=list)

    # Detected anomalies
    anomalies: list[dict[str, Any]] = Field(default_factory=list)

    # Classifications
    classifications: list[dict[str, Any]] = Field(default_factory=list)

    # Alerts sent
    alerts: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    summary: str = ""
    total_samples: int = 0
    total_anomalies: int = 0

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
