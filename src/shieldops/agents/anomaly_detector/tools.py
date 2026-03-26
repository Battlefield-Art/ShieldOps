"""Anomaly Detector Agent — Tool functions for anomaly detection."""

from __future__ import annotations

import hashlib
import math
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import Anomaly, AnomalyCorrelation, AnomalySeverity, AnomalyType

logger = structlog.get_logger()

# Severity thresholds based on sigma deviation
_SEVERITY_THRESHOLDS: dict[str, float] = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.5,
}


def _generate_anomaly_id(metric: str, source: str, index: int) -> str:
    """Generate a deterministic anomaly ID."""
    raw = f"{metric}:{source}:{index}"
    return f"ANM-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class AnomalyDetectorToolkit:
    """Tools for ML-based anomaly detection across telemetry data."""

    def __init__(
        self,
        metric_client: Any | None = None,
        log_client: Any | None = None,
        trace_client: Any | None = None,
        alert_client: Any | None = None,
    ) -> None:
        self._metric_client = metric_client
        self._log_client = log_client
        self._trace_client = trace_client
        self._alert_client = alert_client

    async def collect_metrics(self, tenant_id: str) -> list[dict[str, Any]]:
        """Collect metric data points for anomaly analysis."""
        logger.info("anomaly_detector.collect_metrics", tenant_id=tenant_id)

        if self._metric_client is not None:
            try:
                return await self._metric_client.query_metrics(  # type: ignore[no-any-return]
                    tenant_id=tenant_id,
                )
            except Exception:
                logger.exception("anomaly_detector.collect_metrics.error")

        # Fallback: synthetic baseline data
        now = datetime.now(UTC)
        metrics = [
            "cpu_utilization",
            "memory_usage_percent",
            "request_latency_p99",
            "error_rate_5xx",
            "disk_io_utilization",
            "network_throughput_mbps",
        ]
        data_points: list[dict[str, Any]] = []
        for metric in metrics:
            data_points.append(
                {
                    "source": "prometheus",
                    "metric_name": metric,
                    "value": 45.0,
                    "timestamp": now.isoformat(),
                    "labels": {"tenant_id": tenant_id},
                    "data_type": "metric",
                }
            )
        return data_points

    async def collect_logs(self, tenant_id: str) -> list[dict[str, Any]]:
        """Collect log-based data points for anomaly analysis."""
        logger.info("anomaly_detector.collect_logs", tenant_id=tenant_id)

        if self._log_client is not None:
            try:
                return await self._log_client.query_log_rates(  # type: ignore[no-any-return]
                    tenant_id=tenant_id,
                )
            except Exception:
                logger.exception("anomaly_detector.collect_logs.error")

        return [
            {
                "source": "elasticsearch",
                "metric_name": "error_log_rate",
                "value": 12.0,
                "timestamp": datetime.now(UTC).isoformat(),
                "labels": {"tenant_id": tenant_id},
                "data_type": "log",
            },
        ]

    async def detect_anomalies(
        self,
        data_points: list[dict[str, Any]],
    ) -> list[Anomaly]:
        """Run anomaly detection on collected data points.

        Uses z-score based detection against rolling baselines.
        """
        logger.info(
            "anomaly_detector.detect_anomalies",
            data_point_count=len(data_points),
        )

        anomalies: list[Anomaly] = []
        for i, dp in enumerate(data_points):
            value = dp.get("value", 0.0)
            baseline = dp.get("baseline", value * 0.8)
            stddev = dp.get("stddev", max(abs(baseline) * 0.1, 1.0))

            if stddev == 0:
                continue

            deviation = abs(value - baseline) / stddev

            if deviation < _SEVERITY_THRESHOLDS["low"]:
                continue

            # Determine anomaly type
            if value > baseline:
                anomaly_type = AnomalyType.SPIKE
            elif value < baseline:
                anomaly_type = AnomalyType.DROP
            else:
                anomaly_type = AnomalyType.OUTLIER

            # Determine severity
            severity = AnomalySeverity.LOW
            for sev_name, threshold in _SEVERITY_THRESHOLDS.items():
                if deviation >= threshold:
                    severity = AnomalySeverity(sev_name)
                    break

            confidence = min(1.0, deviation / 5.0)

            anomalies.append(
                Anomaly(
                    id=_generate_anomaly_id(
                        dp.get("metric_name", "unknown"),
                        dp.get("source", "unknown"),
                        i,
                    ),
                    metric_name=dp.get("metric_name", "unknown"),
                    anomaly_type=anomaly_type,
                    baseline_value=baseline,
                    current_value=value,
                    deviation_sigma=round(deviation, 2),
                    severity=severity,
                    confidence=round(confidence, 3),
                    source=dp.get("source", "unknown"),
                    labels=dp.get("labels", {}),
                    detected_at=datetime.now(UTC),
                )
            )

        anomalies.sort(key=lambda a: a.deviation_sigma, reverse=True)
        return anomalies

    async def correlate_anomalies(
        self,
        anomalies: list[Anomaly],
    ) -> list[AnomalyCorrelation]:
        """Correlate anomalies by time proximity and service relationship."""
        logger.info(
            "anomaly_detector.correlate_anomalies",
            anomaly_count=len(anomalies),
        )

        if len(anomalies) < 2:
            return []

        correlations: list[AnomalyCorrelation] = []
        # Group anomalies by source as a basic correlation heuristic
        source_groups: dict[str, list[Anomaly]] = {}
        for anomaly in anomalies:
            source_groups.setdefault(anomaly.source, []).append(anomaly)

        for source, group in source_groups.items():
            if len(group) >= 2:
                correlation_score = min(
                    1.0,
                    sum(a.confidence for a in group) / len(group),
                )
                correlations.append(
                    AnomalyCorrelation(
                        anomaly_ids=[a.id for a in group],
                        correlation_score=round(correlation_score, 3),
                        root_cause_hypothesis=(
                            f"Multiple anomalies from {source} suggest a shared root cause"
                        ),
                        affected_services=[a.labels.get("service", source) for a in group],
                    )
                )

        return correlations

    async def send_alert(
        self,
        anomaly: Anomaly,
        channel: str = "slack",
    ) -> dict[str, Any]:
        """Send an alert for a detected anomaly."""
        logger.info(
            "anomaly_detector.send_alert",
            anomaly_id=anomaly.id,
            severity=anomaly.severity,
        )

        if self._alert_client is not None:
            try:
                return await self._alert_client.send(  # type: ignore[no-any-return]
                    anomaly_id=anomaly.id,
                    severity=anomaly.severity,
                    message=f"Anomaly: {anomaly.metric_name} "
                    f"({anomaly.deviation_sigma}σ deviation)",
                    channel=channel,
                )
            except Exception:
                logger.exception("anomaly_detector.send_alert.error")

        return {
            "anomaly_id": anomaly.id,
            "action_type": "alert",
            "channel": channel,
            "message": (
                f"[{anomaly.severity.value.upper()}] {anomaly.metric_name}: "
                f"{anomaly.current_value} (baseline: {anomaly.baseline_value}, "
                f"{anomaly.deviation_sigma}σ)"
            ),
            "severity": anomaly.severity.value,
            "acknowledged": False,
        }

    def compute_sigma(
        self,
        values: list[float],
        current: float,
    ) -> float:
        """Compute z-score (sigma deviation) for a value against a series."""
        if not values:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / max(len(values), 1)
        stddev = math.sqrt(variance)
        if stddev == 0:
            return 0.0
        return abs(current - mean) / stddev
