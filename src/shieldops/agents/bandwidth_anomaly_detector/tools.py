"""Bandwidth Anomaly Detector Agent — Tool functions."""

from __future__ import annotations

import hashlib
import math
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import (
    AnomalyAlert,
    AnomalyCategory,
    BaselineProfile,
    TrafficDirection,
)

logger = structlog.get_logger()

_SEVERITY_THRESHOLDS: dict[str, float] = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.5,
}

# Well-known ports for traffic classification
_CRYPTO_PORTS = {3333, 4444, 8333, 8545, 9999, 14444, 30303}
_TORRENT_PORTS = {6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889}


def _generate_alert_id(entity: str, category: str, index: int) -> str:
    """Generate a deterministic alert ID."""
    raw = f"{entity}:{category}:{index}"
    return f"BWA-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class BandwidthAnomalyDetectorToolkit:
    """Tools for bandwidth anomaly detection and traffic analysis."""

    def __init__(
        self,
        netflow_client: Any | None = None,
        firewall_client: Any | None = None,
        alert_client: Any | None = None,
    ) -> None:
        self._netflow_client = netflow_client
        self._firewall_client = firewall_client
        self._alert_client = alert_client

    async def collect_samples(self, tenant_id: str) -> list[dict[str, Any]]:
        """Collect bandwidth samples from netflow/firewall sources."""
        logger.info(
            "bandwidth_anomaly.collect_samples",
            tenant_id=tenant_id,
        )

        if self._netflow_client is not None:
            try:
                return await self._netflow_client.query_flows(
                    tenant_id=tenant_id,
                )
            except Exception:
                logger.exception("bandwidth_anomaly.collect_samples.error")

        now = datetime.now(UTC)
        return [
            {
                "source_ip": "10.0.1.50",
                "dest_ip": "203.0.113.10",
                "direction": "outbound",
                "bytes_transferred": 524_288_000,
                "packets": 380_000,
                "protocol": "tcp",
                "port": 443,
                "timestamp": now.isoformat(),
                "interface": "eth0",
                "labels": {"tenant_id": tenant_id},
            },
            {
                "source_ip": "10.0.2.15",
                "dest_ip": "198.51.100.5",
                "direction": "outbound",
                "bytes_transferred": 8_500_000,
                "packets": 6_200,
                "protocol": "tcp",
                "port": 4444,
                "timestamp": now.isoformat(),
                "interface": "eth0",
                "labels": {"tenant_id": tenant_id},
            },
            {
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.1.200",
                "direction": "lateral",
                "bytes_transferred": 1_200_000_000,
                "packets": 850_000,
                "protocol": "tcp",
                "port": 445,
                "timestamp": now.isoformat(),
                "interface": "eth1",
                "labels": {"tenant_id": tenant_id},
            },
        ]

    async def build_baselines(
        self,
        samples: list[dict[str, Any]],
    ) -> list[BaselineProfile]:
        """Build bandwidth baselines from historical samples."""
        logger.info(
            "bandwidth_anomaly.build_baselines",
            sample_count=len(samples),
        )

        entity_data: dict[str, list[int]] = {}
        for s in samples:
            src = s.get("source_ip", "unknown")
            entity_data.setdefault(src, []).append(s.get("bytes_transferred", 0))

        baselines: list[BaselineProfile] = []
        for entity, values in entity_data.items():
            if not values:
                continue
            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / max(len(values), 1)
            stddev = math.sqrt(variance)
            baselines.append(
                BaselineProfile(
                    entity=entity,
                    direction=TrafficDirection.OUTBOUND,
                    avg_bytes_per_hour=mean,
                    stddev_bytes=max(stddev, 1.0),
                    peak_bytes_per_hour=float(max(values)),
                    active_hours=list(range(8, 18)),
                    sample_count=len(values),
                    last_updated=datetime.now(UTC),
                )
            )
        return baselines

    async def detect_anomalies(
        self,
        samples: list[dict[str, Any]],
        baselines: list[BaselineProfile],
    ) -> list[AnomalyAlert]:
        """Detect bandwidth anomalies against baselines."""
        logger.info(
            "bandwidth_anomaly.detect_anomalies",
            sample_count=len(samples),
            baseline_count=len(baselines),
        )

        baseline_map: dict[str, BaselineProfile] = {b.entity: b for b in baselines}
        alerts: list[AnomalyAlert] = []

        for i, sample in enumerate(samples):
            src = sample.get("source_ip", "unknown")
            bw = sample.get("bytes_transferred", 0)
            port = sample.get("port", 0)
            direction = sample.get("direction", "unknown")

            baseline = baseline_map.get(src)
            if baseline is None:
                continue

            stddev = max(baseline.stddev_bytes, 1.0)
            deviation = abs(bw - baseline.avg_bytes_per_hour) / stddev

            category = self._classify_port(port, bw, direction)

            if deviation < _SEVERITY_THRESHOLDS["low"]:
                if category in (
                    AnomalyCategory.CRYPTO_MINING,
                    AnomalyCategory.TORRENT_ACTIVITY,
                ):
                    deviation = 2.0
                else:
                    continue

            severity = "low"
            for sev_name, threshold in _SEVERITY_THRESHOLDS.items():
                if deviation >= threshold:
                    severity = sev_name
                    break

            confidence = min(1.0, deviation / 5.0)

            alerts.append(
                AnomalyAlert(
                    alert_id=_generate_alert_id(src, category.value, i),
                    entity=src,
                    category=category,
                    direction=TrafficDirection(direction),
                    current_bytes=bw,
                    baseline_bytes=baseline.avg_bytes_per_hour,
                    deviation_sigma=round(deviation, 2),
                    confidence=round(confidence, 3),
                    severity=severity,
                    description=(
                        f"{category.value}: {src} transferred "
                        f"{bw:,} bytes (baseline "
                        f"{baseline.avg_bytes_per_hour:,.0f})"
                    ),
                    detected_at=datetime.now(UTC),
                    labels=sample.get("labels", {}),
                )
            )

        alerts.sort(key=lambda a: a.deviation_sigma, reverse=True)
        return alerts

    def _classify_port(
        self,
        port: int,
        bytes_transferred: int,
        direction: str,
    ) -> AnomalyCategory:
        """Classify traffic category based on port and volume."""
        if port in _CRYPTO_PORTS:
            return AnomalyCategory.CRYPTO_MINING
        if port in _TORRENT_PORTS:
            return AnomalyCategory.TORRENT_ACTIVITY
        if direction == "outbound" and bytes_transferred > 100_000_000:
            return AnomalyCategory.LARGE_EGRESS
        if direction == "lateral":
            return AnomalyCategory.SHADOW_IT
        return AnomalyCategory.TRAFFIC_SPIKE

    async def send_alert(
        self,
        alert: AnomalyAlert,
        channel: str = "slack",
    ) -> dict[str, Any]:
        """Send an alert for a bandwidth anomaly."""
        logger.info(
            "bandwidth_anomaly.send_alert",
            alert_id=alert.alert_id,
            severity=alert.severity,
        )

        if self._alert_client is not None:
            try:
                return await self._alert_client.send(
                    alert_id=alert.alert_id,
                    severity=alert.severity,
                    message=alert.description,
                    channel=channel,
                )
            except Exception:
                logger.exception("bandwidth_anomaly.send_alert.error")

        return {
            "alert_id": alert.alert_id,
            "action_type": "alert",
            "channel": channel,
            "message": (
                f"[{alert.severity.upper()}] "
                f"{alert.category.value}: {alert.entity} — "
                f"{alert.current_bytes:,} bytes "
                f"({alert.deviation_sigma}\u03c3)"
            ),
            "severity": alert.severity,
            "acknowledged": False,
        }

    def compute_sigma(
        self,
        values: list[float],
        current: float,
    ) -> float:
        """Compute z-score for a value against a series."""
        if not values:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / max(len(values), 1)
        stddev = math.sqrt(variance)
        if stddev == 0:
            return 0.0
        return abs(current - mean) / stddev
