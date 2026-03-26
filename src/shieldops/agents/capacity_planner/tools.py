"""Capacity Planner Agent — Tool functions for capacity analysis."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    Bottleneck,
    CapacityRisk,
    DemandForecast,
    ResourceMetric,
    ResourceType,
    ScalingPlan,
)

logger = structlog.get_logger()

# Simulated resource profiles per service type
_RESOURCE_PROFILES: dict[str, list[dict[str, Any]]] = {
    "api_gateway": [
        {
            "resource_type": ResourceType.COMPUTE,
            "base_usage": 62.0,
            "peak_factor": 1.4,
            "trend": "increasing",
            "exhaustion_days": 45,
        },
        {
            "resource_type": ResourceType.MEMORY,
            "base_usage": 71.0,
            "peak_factor": 1.25,
            "trend": "stable",
            "exhaustion_days": 90,
        },
        {
            "resource_type": ResourceType.NETWORK,
            "base_usage": 55.0,
            "peak_factor": 1.8,
            "trend": "increasing",
            "exhaustion_days": 60,
        },
    ],
    "database_cluster": [
        {
            "resource_type": ResourceType.DATABASE,
            "base_usage": 78.0,
            "peak_factor": 1.15,
            "trend": "increasing",
            "exhaustion_days": 21,
        },
        {
            "resource_type": ResourceType.STORAGE,
            "base_usage": 82.0,
            "peak_factor": 1.05,
            "trend": "increasing",
            "exhaustion_days": 14,
        },
        {
            "resource_type": ResourceType.MEMORY,
            "base_usage": 68.0,
            "peak_factor": 1.3,
            "trend": "stable",
            "exhaustion_days": 120,
        },
    ],
    "worker_pool": [
        {
            "resource_type": ResourceType.COMPUTE,
            "base_usage": 85.0,
            "peak_factor": 1.1,
            "trend": "increasing",
            "exhaustion_days": 10,
        },
        {
            "resource_type": ResourceType.MEMORY,
            "base_usage": 74.0,
            "peak_factor": 1.35,
            "trend": "increasing",
            "exhaustion_days": 30,
        },
    ],
    "default": [
        {
            "resource_type": ResourceType.COMPUTE,
            "base_usage": 50.0,
            "peak_factor": 1.5,
            "trend": "stable",
            "exhaustion_days": 180,
        },
        {
            "resource_type": ResourceType.MEMORY,
            "base_usage": 55.0,
            "peak_factor": 1.3,
            "trend": "stable",
            "exhaustion_days": 150,
        },
        {
            "resource_type": ResourceType.STORAGE,
            "base_usage": 40.0,
            "peak_factor": 1.1,
            "trend": "increasing",
            "exhaustion_days": 200,
        },
        {
            "resource_type": ResourceType.NETWORK,
            "base_usage": 30.0,
            "peak_factor": 1.6,
            "trend": "stable",
            "exhaustion_days": 365,
        },
        {
            "resource_type": ResourceType.DATABASE,
            "base_usage": 45.0,
            "peak_factor": 1.2,
            "trend": "stable",
            "exhaustion_days": 240,
        },
    ],
}

# Seasonal patterns by month quartile
_SEASONAL_PATTERNS = [
    "end_of_quarter_spike",
    "holiday_traffic",
    "batch_processing_window",
    "steady_state",
    "marketing_campaign",
]

# Scaling action templates by resource type
_SCALING_ACTIONS: dict[ResourceType, dict[str, Any]] = {
    ResourceType.COMPUTE: {
        "action": "horizontal_scale_out",
        "unit": "vCPU",
        "cost_per_unit": 72.0,
    },
    ResourceType.MEMORY: {
        "action": "vertical_scale_up",
        "unit": "GiB",
        "cost_per_unit": 12.0,
    },
    ResourceType.STORAGE: {
        "action": "expand_volume",
        "unit": "TiB",
        "cost_per_unit": 92.0,
    },
    ResourceType.NETWORK: {
        "action": "upgrade_bandwidth",
        "unit": "Gbps",
        "cost_per_unit": 45.0,
    },
    ResourceType.DATABASE: {
        "action": "scale_replica_set",
        "unit": "replicas",
        "cost_per_unit": 350.0,
    },
}


def _resource_id(tenant: str, service: str, rtype: str, idx: int) -> str:
    """Generate a deterministic resource ID."""
    raw = f"{tenant}:{service}:{rtype}:{idx}"
    return f"RES-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


def _severity_from_days(days: int) -> CapacityRisk:
    """Map days-to-exhaustion to a capacity risk level."""
    if days <= 7:
        return CapacityRisk.CRITICAL
    if days <= 30:
        return CapacityRisk.HIGH
    if days <= 90:
        return CapacityRisk.MEDIUM
    if days <= 180:
        return CapacityRisk.LOW
    return CapacityRisk.HEALTHY


class CapacityPlannerToolkit:
    """Tools for resource capacity collection, forecasting, and planning."""

    def __init__(
        self,
        metrics_client: Any | None = None,
        cloud_provider: Any | None = None,
        cost_api: Any | None = None,
    ) -> None:
        self._metrics_client = metrics_client
        self._cloud_provider = cloud_provider
        self._cost_api = cost_api

    async def collect_resource_metrics(
        self,
        tenant_id: str,
        services: list[str] | None = None,
    ) -> list[ResourceMetric]:
        """Collect current resource utilisation metrics.

        Uses a live metrics client when available, otherwise generates
        realistic simulated data per service profile.
        """
        logger.info(
            "capacity_planner.collect_metrics",
            tenant_id=tenant_id,
            services=services,
        )

        if self._metrics_client is not None:
            try:
                raw = await self._metrics_client.get_metrics(tenant_id=tenant_id, services=services)
                return [ResourceMetric(**m) for m in raw]
            except Exception:
                logger.exception("capacity_planner.collect_metrics.error")

        target_services = services or ["api_gateway", "database_cluster", "worker_pool"]
        metrics: list[ResourceMetric] = []
        idx = 0

        for svc in target_services:
            svc_lower = svc.lower()
            if "api" in svc_lower or "gateway" in svc_lower:
                profile_key = "api_gateway"
            elif "db" in svc_lower or "database" in svc_lower:
                profile_key = "database_cluster"
            elif "worker" in svc_lower or "queue" in svc_lower:
                profile_key = "worker_pool"
            else:
                profile_key = "default"

            for rp in _RESOURCE_PROFILES[profile_key]:
                noise = random.gauss(0, 3.0)
                current = round(max(0.0, min(100.0, rp["base_usage"] + noise)), 1)
                peak = round(min(100.0, current * rp["peak_factor"]), 1)
                days = max(1, rp["exhaustion_days"] + random.randint(-5, 5))  # noqa: S311

                metrics.append(
                    ResourceMetric(
                        id=f"MET-{idx:04d}",
                        resource_id=_resource_id(tenant_id, svc, rp["resource_type"].value, idx),
                        resource_type=rp["resource_type"],
                        current_usage_pct=current,
                        peak_usage_pct=peak,
                        trend=rp["trend"],
                        days_to_exhaustion=days,
                        service=svc,
                    )
                )
                idx += 1

        return metrics

    async def forecast_demand(
        self,
        metrics: list[ResourceMetric],
        horizon_days: int = 30,
    ) -> list[DemandForecast]:
        """Produce demand forecasts for each collected metric.

        Uses the trend direction and current usage to project forward.
        """
        logger.info(
            "capacity_planner.forecast_demand",
            metric_count=len(metrics),
            horizon_days=horizon_days,
        )

        forecasts: list[DemandForecast] = []
        for i, m in enumerate(metrics):
            if m.trend == "increasing":
                growth_rate = random.uniform(0.3, 0.8)  # noqa: S311
            elif m.trend == "decreasing":
                growth_rate = random.uniform(-0.4, -0.1)  # noqa: S311
            else:
                growth_rate = random.uniform(-0.05, 0.15)  # noqa: S311

            projected = m.current_usage_pct + (growth_rate * horizon_days / 30.0) * 10.0
            projected = round(max(0.0, min(100.0, projected)), 1)
            confidence = round(random.uniform(0.6, 0.95), 2)  # noqa: S311
            pattern = random.choice(_SEASONAL_PATTERNS)  # noqa: S311

            forecasts.append(
                DemandForecast(
                    id=f"FCST-{i:04d}",
                    resource_id=m.resource_id,
                    forecasted_usage_pct=projected,
                    forecast_horizon_days=horizon_days,
                    confidence=confidence,
                    seasonal_pattern=pattern,
                )
            )

        return forecasts

    async def identify_bottlenecks(
        self,
        metrics: list[ResourceMetric],
        forecasts: list[DemandForecast],
    ) -> list[Bottleneck]:
        """Identify resources that are at risk of exhaustion.

        Combines current metrics with forecasts to flag bottlenecks.
        """
        logger.info(
            "capacity_planner.identify_bottlenecks",
            metric_count=len(metrics),
        )

        forecast_map: dict[str, DemandForecast] = {f.resource_id: f for f in forecasts}
        bottlenecks: list[Bottleneck] = []
        idx = 0

        for m in metrics:
            severity = _severity_from_days(m.days_to_exhaustion)
            if severity == CapacityRisk.HEALTHY:
                continue

            forecast = forecast_map.get(m.resource_id)
            forecasted_pct = forecast.forecasted_usage_pct if forecast else m.current_usage_pct

            if forecasted_pct >= 90.0 and severity in (
                CapacityRisk.CRITICAL,
                CapacityRisk.HIGH,
            ):
                severity = CapacityRisk.CRITICAL

            bottlenecks.append(
                Bottleneck(
                    id=f"BTL-{idx:04d}",
                    resource_id=m.resource_id,
                    resource_type=m.resource_type,
                    severity=severity,
                    description=(
                        f"{m.resource_type.value} for {m.service} at "
                        f"{m.current_usage_pct}% (peak {m.peak_usage_pct}%), "
                        f"forecast {forecasted_pct}% in "
                        f"{forecast.forecast_horizon_days if forecast else '?'}d"
                    ),
                    impact=(
                        f"Exhaustion in ~{m.days_to_exhaustion} days — "
                        f"risk of service degradation for {m.service}"
                    ),
                    mitigation=(
                        f"Scale {m.resource_type.value} capacity before "
                        f"reaching {m.peak_usage_pct}% threshold"
                    ),
                )
            )
            idx += 1

        # Sort by severity
        severity_order = {
            CapacityRisk.CRITICAL: 0,
            CapacityRisk.HIGH: 1,
            CapacityRisk.MEDIUM: 2,
            CapacityRisk.LOW: 3,
            CapacityRisk.HEALTHY: 4,
        }
        bottlenecks.sort(key=lambda b: severity_order.get(b.severity, 5))
        return bottlenecks

    async def plan_scaling(
        self,
        bottlenecks: list[Bottleneck],
        metrics: list[ResourceMetric],
    ) -> list[ScalingPlan]:
        """Generate scaling plans for each identified bottleneck.

        Uses cloud provider APIs when available, otherwise estimates
        from built-in scaling templates.
        """
        logger.info(
            "capacity_planner.plan_scaling",
            bottleneck_count=len(bottlenecks),
        )

        if self._cloud_provider is not None:
            try:
                raw = await self._cloud_provider.get_scaling_plans(
                    bottlenecks=[b.model_dump() for b in bottlenecks]
                )
                return [ScalingPlan(**p) for p in raw]
            except Exception:
                logger.exception("capacity_planner.plan_scaling.error")

        metric_map: dict[str, ResourceMetric] = {m.resource_id: m for m in metrics}
        plans: list[ScalingPlan] = []

        for i, btl in enumerate(bottlenecks):
            tmpl = _SCALING_ACTIONS.get(
                btl.resource_type,
                _SCALING_ACTIONS[ResourceType.COMPUTE],
            )
            m = metric_map.get(btl.resource_id)
            current_val = int(m.current_usage_pct) if m else 50
            recommended_val = min(100, current_val + random.randint(20, 50))  # noqa: S311
            units_needed = max(1, (recommended_val - current_val) // 10)
            cost_delta = round(units_needed * tmpl["cost_per_unit"], 2)

            auto_scalable = btl.resource_type in (
                ResourceType.COMPUTE,
                ResourceType.NETWORK,
            )

            plans.append(
                ScalingPlan(
                    id=f"PLAN-{i:04d}",
                    resource_id=btl.resource_id,
                    action=tmpl["action"],
                    current_capacity=f"{current_val} {tmpl['unit']}",
                    recommended_capacity=f"{recommended_val} {tmpl['unit']}",
                    estimated_cost_delta=cost_delta,
                    auto_scalable=auto_scalable,
                )
            )

        return plans
