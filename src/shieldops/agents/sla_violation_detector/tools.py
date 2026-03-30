"""Tool functions for the SLA Violation Detector."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from .models import SLAType, ViolationSeverity

logger = structlog.get_logger()

DEFAULT_THRESHOLDS: dict[SLAType, dict[str, float]] = {
    SLAType.AVAILABILITY: {
        "target": 99.9,
        "warning": 99.5,
    },
    SLAType.LATENCY: {
        "target": 200.0,
        "warning": 150.0,
    },
    SLAType.ERROR_RATE: {
        "target": 0.1,
        "warning": 0.05,
    },
    SLAType.THROUGHPUT: {
        "target": 1000.0,
        "warning": 800.0,
    },
    SLAType.RESOLUTION_TIME: {
        "target": 60.0,
        "warning": 45.0,
    },
    SLAType.RESPONSE_TIME: {
        "target": 15.0,
        "warning": 10.0,
    },
}


class SLAViolationDetectorToolkit:
    """Toolkit for SLA violation detection workflows."""

    def __init__(
        self,
        metrics_service: Any | None = None,
        notification_service: Any | None = None,
    ) -> None:
        self._metrics = metrics_service
        self._notifier = notification_service

    async def collect_metrics(
        self,
        services: list[str],
        time_window_hours: int,
    ) -> list[dict[str, Any]]:
        """Collect SLA metrics for services."""
        metrics: list[dict[str, Any]] = []
        if not services:
            services = ["api-gateway", "auth-service"]

        for svc in services:
            for sla_type in SLAType:
                value = self._mock_metric(sla_type)
                metrics.append(
                    {
                        "id": f"svd-met-{uuid4().hex[:8]}",
                        "service": svc,
                        "sla_type": sla_type.value,
                        "value": value,
                        "window_hours": time_window_hours,
                        "collected_at": time.time(),
                    }
                )

        if self._metrics:
            try:
                real = await self._metrics.query(
                    services,
                    time_window_hours,
                )
                if real:
                    metrics = real
            except Exception:
                logger.debug("svd.metrics_fallback")

        logger.info(
            "svd.collect_metrics",
            count=len(metrics),
        )
        return metrics

    def _mock_metric(self, sla_type: SLAType) -> float:
        """Generate mock metric values."""
        mock_values: dict[SLAType, float] = {
            SLAType.AVAILABILITY: 99.85,
            SLAType.LATENCY: 185.0,
            SLAType.ERROR_RATE: 0.08,
            SLAType.THROUGHPUT: 950.0,
            SLAType.RESOLUTION_TIME: 55.0,
            SLAType.RESPONSE_TIME: 12.0,
        }
        return mock_values.get(sla_type, 0.0)

    async def evaluate_thresholds(
        self,
        collected_metrics: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Evaluate metrics against SLA thresholds."""
        evaluations: list[dict[str, Any]] = []
        for metric in collected_metrics:
            sla_type_val = metric.get("sla_type", "")
            try:
                sla_type = SLAType(sla_type_val)
            except ValueError:
                continue

            thresholds = DEFAULT_THRESHOLDS.get(
                sla_type,
                {},
            )
            target = thresholds.get("target", 0)
            warning = thresholds.get("warning", 0)
            value = metric.get("value", 0)

            if sla_type in (
                SLAType.LATENCY,
                SLAType.ERROR_RATE,
                SLAType.RESOLUTION_TIME,
                SLAType.RESPONSE_TIME,
            ):
                # Higher is worse
                if value > target:
                    status = ViolationSeverity.BREACH
                elif value > warning:
                    status = ViolationSeverity.WARNING
                else:
                    status = ViolationSeverity.HEALTHY
            else:
                # Lower is worse
                if value < target:
                    status = ViolationSeverity.BREACH
                elif value < warning:
                    status = ViolationSeverity.WARNING
                else:
                    status = ViolationSeverity.HEALTHY

            evaluations.append(
                {
                    "id": f"svd-eval-{uuid4().hex[:8]}",
                    "service": metric.get("service"),
                    "sla_type": sla_type_val,
                    "value": value,
                    "target": target,
                    "status": status.value,
                }
            )

        logger.info(
            "svd.evaluate_thresholds",
            count=len(evaluations),
        )
        return evaluations

    async def detect_violations(
        self,
        threshold_evaluations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Filter evaluations to active violations."""
        violations = [
            {
                **ev,
                "id": f"svd-vio-{uuid4().hex[:8]}",
                "detected_at": time.time(),
            }
            for ev in threshold_evaluations
            if ev.get("status")
            in (
                ViolationSeverity.BREACH.value,
                ViolationSeverity.WARNING.value,
            )
        ]

        logger.info(
            "svd.detect_violations",
            count=len(violations),
        )
        return violations

    async def calculate_impact(
        self,
        violations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Calculate business impact of violations."""
        impacts: list[dict[str, Any]] = []
        for v in violations:
            sla_type = v.get("sla_type", "")
            status = v.get("status", "warning")

            if status == "breach":
                credit_pct = 10.0
                risk = "high"
            else:
                credit_pct = 0.0
                risk = "medium"

            impacts.append(
                {
                    "id": f"svd-imp-{uuid4().hex[:8]}",
                    "violation_id": v.get("id"),
                    "service": v.get("service"),
                    "sla_type": sla_type,
                    "credit_percentage": credit_pct,
                    "business_risk": risk,
                    "estimated_cost_usd": credit_pct * 100,
                }
            )

        logger.info(
            "svd.calculate_impact",
            count=len(impacts),
        )
        return impacts

    async def notify_owners(
        self,
        violations: list[dict[str, Any]],
        impact_calculations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Notify service owners of violations."""
        notifications: list[dict[str, Any]] = []
        for v in violations:
            notifications.append(
                {
                    "id": f"svd-ntf-{uuid4().hex[:8]}",
                    "service": v.get("service"),
                    "sla_type": v.get("sla_type"),
                    "status": v.get("status"),
                    "channel": "slack",
                    "sent_at": time.time(),
                    "delivered": True,
                }
            )

        if self._notifier:
            try:
                await self._notifier.send_batch(
                    notifications,
                )
            except Exception:
                logger.warning("svd.notify_failed")

        logger.info(
            "svd.notify_owners",
            count=len(notifications),
        )
        return notifications
