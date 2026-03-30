"""Predictive Scaler Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import (
    DemandPattern,
    DemandPrediction,
    MetricSnapshot,
    ResourceType,
    ScalingDirection,
    ScalingExecution,
    ScalingPlan,
)

logger = structlog.get_logger()

_RESOURCE_PROFILES: list[dict[str, Any]] = [
    {
        "resource_id": "eks-prod-api",
        "resource_type": ResourceType.CONTAINER,
        "region": "us-east-1",
        "cpu": 72.0,
        "mem": 65.0,
        "rps": 4200.0,
        "p99": 45.0,
    },
    {
        "resource_id": "eks-prod-worker",
        "resource_type": ResourceType.CONTAINER,
        "region": "us-east-1",
        "cpu": 58.0,
        "mem": 70.0,
        "rps": 1800.0,
        "p99": 120.0,
    },
    {
        "resource_id": "ec2-ml-inference",
        "resource_type": ResourceType.GPU,
        "region": "us-west-2",
        "cpu": 85.0,
        "mem": 78.0,
        "rps": 950.0,
        "p99": 200.0,
    },
    {
        "resource_id": "rds-prod-primary",
        "resource_type": ResourceType.MEMORY,
        "region": "us-east-1",
        "cpu": 45.0,
        "mem": 82.0,
        "rps": 3200.0,
        "p99": 8.0,
    },
    {
        "resource_id": "redis-cache-01",
        "resource_type": ResourceType.MEMORY,
        "region": "us-east-1",
        "cpu": 30.0,
        "mem": 88.0,
        "rps": 15000.0,
        "p99": 1.2,
    },
    {
        "resource_id": "nginx-lb-prod",
        "resource_type": ResourceType.NETWORK,
        "region": "us-east-1",
        "cpu": 40.0,
        "mem": 35.0,
        "rps": 8500.0,
        "p99": 12.0,
    },
    {
        "resource_id": "ebs-analytics",
        "resource_type": ResourceType.STORAGE,
        "region": "us-east-1",
        "cpu": 0.0,
        "mem": 0.0,
        "rps": 500.0,
        "p99": 25.0,
    },
    {
        "resource_id": "gke-data-pipeline",
        "resource_type": ResourceType.COMPUTE,
        "region": "us-central1",
        "cpu": 62.0,
        "mem": 55.0,
        "rps": 2400.0,
        "p99": 90.0,
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class PredictiveScalerToolkit:
    """Tools for predictive infrastructure scaling."""

    def __init__(
        self,
        metrics_api: Any | None = None,
        infra_api: Any | None = None,
    ) -> None:
        self._metrics_api = metrics_api
        self._infra_api = infra_api

    async def collect_metrics(
        self,
        tenant_id: str,
    ) -> list[MetricSnapshot]:
        """Collect current resource utilization metrics."""
        logger.info(
            "ps.collect_metrics",
            tenant_id=tenant_id,
        )

        if self._metrics_api is not None:
            try:
                raw = await self._metrics_api.get_metrics(
                    tenant_id=tenant_id,
                )
                return [MetricSnapshot(**r) for r in raw]
            except Exception:
                logger.exception("ps.collect_metrics.error")

        now = datetime.now(tz=UTC).isoformat()
        snapshots: list[MetricSnapshot] = []
        for i, p in enumerate(_RESOURCE_PROFILES):
            cpu_noise = random.gauss(0, 5.0)  # noqa: S311
            mem_noise = random.gauss(0, 4.0)  # noqa: S311
            rps_noise = random.gauss(0, p["rps"] * 0.1)  # noqa: S311
            snapshots.append(
                MetricSnapshot(
                    id=_gen_id("MS", tenant_id, i),
                    resource_id=p["resource_id"],
                    resource_type=p["resource_type"],
                    region=p["region"],
                    cpu_pct=round(
                        max(0.0, min(100.0, p["cpu"] + cpu_noise)),
                        1,
                    ),
                    memory_pct=round(
                        max(0.0, min(100.0, p["mem"] + mem_noise)),
                        1,
                    ),
                    requests_per_sec=round(
                        max(0.0, p["rps"] + rps_noise),
                        1,
                    ),
                    latency_p99_ms=round(
                        max(0.1, p["p99"] + random.gauss(0, 2)),  # noqa: S311
                        1,
                    ),
                    timestamp=now,
                    tags={"env": "production"},
                )
            )
        return snapshots

    async def analyze_patterns(
        self,
        metrics: list[MetricSnapshot],
    ) -> list[DemandPattern]:
        """Analyze demand patterns from metric history."""
        logger.info(
            "ps.analyze_patterns",
            count=len(metrics),
        )

        patterns: list[DemandPattern] = []
        for i, m in enumerate(metrics):
            trend = "stable"
            if m.cpu_pct > 70.0 or m.memory_pct > 75.0:
                trend = "increasing"
            elif m.cpu_pct < 30.0 and m.memory_pct < 30.0:
                trend = "decreasing"

            ptype = random.choice(  # noqa: S311
                ["daily_cycle", "weekly_cycle", "growth"],
            )
            peak = random.randint(9, 17)  # noqa: S311
            patterns.append(
                DemandPattern(
                    id=_gen_id("DP", m.resource_id, i),
                    resource_id=m.resource_id,
                    pattern_type=ptype,
                    periodicity=("24h" if "daily" in ptype else "7d"),
                    peak_hour_utc=peak,
                    avg_utilization=round(
                        (m.cpu_pct + m.memory_pct) / 2.0,
                        1,
                    ),
                    peak_utilization=round(
                        max(m.cpu_pct, m.memory_pct) * 1.15,
                        1,
                    ),
                    trend=trend,
                    confidence=round(
                        random.uniform(0.7, 0.95),  # noqa: S311
                        2,
                    ),
                )
            )
        return patterns

    async def predict_demand(
        self,
        patterns: list[DemandPattern],
    ) -> list[DemandPrediction]:
        """Predict future demand from patterns."""
        logger.info(
            "ps.predict_demand",
            count=len(patterns),
        )

        predictions: list[DemandPrediction] = []
        for i, p in enumerate(patterns):
            growth = 1.15 if p.trend == "increasing" else 1.0
            pred_cpu = round(
                min(100.0, p.peak_utilization * growth),
                1,
            )
            pred_mem = round(
                min(100.0, p.avg_utilization * growth * 1.1),
                1,
            )
            breach = pred_cpu > 80.0 or pred_mem > 85.0

            direction = ScalingDirection.NO_CHANGE
            if breach and p.trend == "increasing":
                direction = ScalingDirection.SCALE_OUT
            elif pred_cpu > 85.0:
                direction = ScalingDirection.SCALE_UP
            elif p.trend == "decreasing":
                direction = ScalingDirection.SCALE_IN

            predictions.append(
                DemandPrediction(
                    id=_gen_id("PR", p.resource_id, i),
                    resource_id=p.resource_id,
                    resource_type=ResourceType.COMPUTE,
                    predicted_cpu_pct=pred_cpu,
                    predicted_memory_pct=pred_mem,
                    predicted_rps=round(
                        p.avg_utilization * 50 * growth,
                        1,
                    ),
                    horizon_minutes=60,
                    confidence=round(
                        p.confidence * 0.9,
                        2,
                    ),
                    breach_threshold=breach,
                    recommended_direction=direction,
                )
            )
        return predictions

    async def plan_scaling(
        self,
        predictions: list[DemandPrediction],
    ) -> list[ScalingPlan]:
        """Create scaling plans from predictions."""
        logger.info(
            "ps.plan_scaling",
            count=len(predictions),
        )

        plans: list[ScalingPlan] = []
        for i, pred in enumerate(predictions):
            if pred.recommended_direction == (ScalingDirection.NO_CHANGE):
                continue

            current = random.randint(2, 8)  # noqa: S311
            target = current
            cost_delta = 0.0

            if pred.recommended_direction in (
                ScalingDirection.SCALE_OUT,
                ScalingDirection.SCALE_UP,
            ):
                target = current + random.randint(1, 3)  # noqa: S311
                cost_delta = round(
                    (target - current) * 45.0,
                    2,
                )
            elif pred.recommended_direction in (
                ScalingDirection.SCALE_IN,
                ScalingDirection.SCALE_DOWN,
            ):
                target = max(1, current - 1)
                cost_delta = round(
                    (target - current) * 45.0,
                    2,
                )

            plans.append(
                ScalingPlan(
                    id=_gen_id("SP", pred.resource_id, i),
                    resource_id=pred.resource_id,
                    resource_type=pred.resource_type,
                    direction=pred.recommended_direction,
                    current_capacity=current,
                    target_capacity=target,
                    reason=(
                        f"Predicted {pred.predicted_cpu_pct}% CPU in {pred.horizon_minutes}min"
                    ),
                    estimated_cost_delta=cost_delta,
                    auto_executable=pred.confidence > 0.8,
                    priority=("high" if pred.breach_threshold else "medium"),
                )
            )
        return plans

    async def execute_scaling(
        self,
        plans: list[ScalingPlan],
    ) -> list[ScalingExecution]:
        """Execute approved scaling plans."""
        logger.info(
            "ps.execute_scaling",
            count=len(plans),
        )

        results: list[ScalingExecution] = []
        for i, plan in enumerate(plans):
            if not plan.auto_executable:
                results.append(
                    ScalingExecution(
                        id=_gen_id("SE", plan.id, i),
                        plan_id=plan.id,
                        status="pending_approval",
                        previous_capacity=plan.current_capacity,
                        new_capacity=plan.current_capacity,
                        latency_ms=0.0,
                        rollback_available=True,
                    )
                )
            else:
                results.append(
                    ScalingExecution(
                        id=_gen_id("SE", plan.id, i),
                        plan_id=plan.id,
                        status="applied",
                        previous_capacity=plan.current_capacity,
                        new_capacity=plan.target_capacity,
                        latency_ms=round(
                            random.uniform(800, 5000),  # noqa: S311
                            1,
                        ),
                        rollback_available=True,
                    )
                )
        return results
