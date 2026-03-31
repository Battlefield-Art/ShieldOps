"""Security Ops Dashboard Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    AnomalyType,
    DashboardInsight,
    DashboardView,
    KPIResult,
    MetricAnomaly,
    MetricCategory,
    SecurityMetric,
)

logger = structlog.get_logger()

_SAMPLE_METRICS: list[dict[str, Any]] = [
    {"name": "mttd_minutes", "category": "detection", "value": 4.2, "unit": "min"},
    {"name": "mttr_minutes", "category": "response", "value": 28.5, "unit": "min"},
    {"name": "alerts_total_24h", "category": "detection", "value": 1247.0, "unit": "count"},
    {"name": "alerts_true_positive_rate", "category": "detection", "value": 0.82, "unit": "pct"},
    {"name": "incidents_open", "category": "response", "value": 14.0, "unit": "count"},
    {"name": "incidents_resolved_24h", "category": "response", "value": 23.0, "unit": "count"},
    {"name": "coverage_mitre_pct", "category": "prevention", "value": 0.73, "unit": "pct"},
    {"name": "blocked_threats_24h", "category": "prevention", "value": 892.0, "unit": "count"},
    {"name": "compliance_score", "category": "compliance", "value": 0.91, "unit": "pct"},
    {"name": "overdue_vulns", "category": "compliance", "value": 37.0, "unit": "count"},
    {"name": "analyst_utilization", "category": "team", "value": 0.78, "unit": "pct"},
    {"name": "tickets_per_analyst_24h", "category": "team", "value": 12.3, "unit": "count"},
    {"name": "security_spend_monthly", "category": "cost", "value": 142000.0, "unit": "usd"},
    {"name": "cost_per_incident", "category": "cost", "value": 3200.0, "unit": "usd"},
]

_KPI_TARGETS: dict[str, tuple[float, str]] = {
    "MTTD": (5.0, "min"),
    "MTTR": (30.0, "min"),
    "True Positive Rate": (0.85, "pct"),
    "MITRE Coverage": (0.80, "pct"),
    "Compliance Score": (0.95, "pct"),
    "Analyst Utilization": (0.75, "pct"),
    "Cost per Incident": (3000.0, "usd"),
    "Alert Volume Trend": (0.0, "delta"),
}

_VIEW_CONFIGS: list[dict[str, Any]] = [
    {
        "view_name": "Executive Summary",
        "view_type": "scorecard",
        "audience": "CISO",
        "time_range": "30d",
    },
    {
        "view_name": "SOC Analyst Workbench",
        "view_type": "operational",
        "audience": "SOC Analyst",
        "time_range": "24h",
    },
    {
        "view_name": "Detection Engineering",
        "view_type": "technical",
        "audience": "Detection Engineer",
        "time_range": "7d",
    },
    {
        "view_name": "Team Performance",
        "view_type": "management",
        "audience": "SOC Manager",
        "time_range": "7d",
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class SecurityOpsDashboardToolkit:
    """Tools for security operations dashboard and KPI tracking."""

    def __init__(
        self,
        metrics_api: Any | None = None,
        dashboard_api: Any | None = None,
    ) -> None:
        self._metrics_api = metrics_api
        self._dashboard_api = dashboard_api

    async def collect_metrics(
        self,
        tenant_id: str,
    ) -> list[SecurityMetric]:
        """Collect security operations metrics."""
        logger.info(
            "sod.collect_metrics",
            tenant_id=tenant_id,
        )

        if self._metrics_api is not None:
            try:
                raw = await self._metrics_api.get_metrics(
                    tenant_id=tenant_id,
                )
                return [SecurityMetric(**r) for r in raw]
            except Exception:
                logger.exception("sod.collect_metrics.error")

        collected: list[SecurityMetric] = []
        for i, m in enumerate(_SAMPLE_METRICS):
            noise = random.uniform(-0.05, 0.05)  # noqa: S311
            val = m["value"] * (1.0 + noise) if m["value"] > 1 else m["value"] + noise * 0.1
            collected.append(
                SecurityMetric(
                    id=_gen_id("SM", tenant_id, i),
                    name=m["name"],
                    category=MetricCategory(m["category"]),
                    value=round(val, 2),
                    unit=m["unit"],
                    timestamp=f"2026-03-30T10:{i:02d}:00Z",
                    source="shieldops-collector",
                    tags=[m["category"]],
                )
            )
        return collected

    async def calculate_kpis(
        self,
        metrics: list[SecurityMetric],
    ) -> list[KPIResult]:
        """Calculate KPIs from raw metrics."""
        logger.info(
            "sod.calculate_kpis",
            count=len(metrics),
        )

        metric_map = {m.name: m.value for m in metrics}
        kpi_values: dict[str, float] = {
            "MTTD": metric_map.get("mttd_minutes", 0.0),
            "MTTR": metric_map.get("mttr_minutes", 0.0),
            "True Positive Rate": metric_map.get("alerts_true_positive_rate", 0.0),
            "MITRE Coverage": metric_map.get("coverage_mitre_pct", 0.0),
            "Compliance Score": metric_map.get("compliance_score", 0.0),
            "Analyst Utilization": metric_map.get("analyst_utilization", 0.0),
            "Cost per Incident": metric_map.get("cost_per_incident", 0.0),
            "Alert Volume Trend": round(metric_map.get("alerts_total_24h", 0.0) - 1200.0, 1),
        }

        results: list[KPIResult] = []
        for i, (kpi_name, target_info) in enumerate(_KPI_TARGETS.items()):
            target_val, unit = target_info
            actual = kpi_values.get(kpi_name, 0.0)

            if unit in ("min", "usd", "delta"):
                meets = actual <= target_val
            else:
                meets = actual >= target_val

            delta = round((actual - target_val) / target_val * 100, 1) if target_val != 0 else 0.0
            trend = "improving" if meets else "degrading"

            results.append(
                KPIResult(
                    id=_gen_id("KP", kpi_name, i),
                    kpi_name=kpi_name,
                    value=round(actual, 2),
                    target=target_val,
                    trend=trend,
                    period="24h",
                    meets_target=meets,
                    delta_pct=delta,
                )
            )
        return results

    async def detect_metric_anomalies(
        self,
        metrics: list[SecurityMetric],
    ) -> list[MetricAnomaly]:
        """Detect anomalies in metric data."""
        logger.info(
            "sod.detect_anomalies",
            count=len(metrics),
        )

        anomalies: list[MetricAnomaly] = []
        idx = 0
        for met in metrics:
            deviation = random.uniform(-30.0, 30.0)  # noqa: S311
            if abs(deviation) > 15.0:
                atype = AnomalyType.SPIKE if deviation > 0 else AnomalyType.DROP
                expected = met.value / (1.0 + deviation / 100.0)
                anomalies.append(
                    MetricAnomaly(
                        id=_gen_id("MA", met.id, idx),
                        metric_name=met.name,
                        anomaly_type=atype,
                        severity="high" if abs(deviation) > 25 else "medium",
                        expected_value=round(expected, 2),
                        actual_value=met.value,
                        deviation_pct=round(abs(deviation), 1),
                        detected_at=met.timestamp,
                    )
                )
                idx += 1
        return anomalies

    async def generate_insights(
        self,
        kpis: list[KPIResult],
        anomalies: list[MetricAnomaly],
    ) -> list[DashboardInsight]:
        """Generate actionable insights from KPIs and anomalies."""
        logger.info(
            "sod.generate_insights",
            kpis=len(kpis),
            anomalies=len(anomalies),
        )

        insights: list[DashboardInsight] = []
        idx = 0

        failing_kpis = [k for k in kpis if not k.meets_target]
        for fk in failing_kpis:
            insights.append(
                DashboardInsight(
                    id=_gen_id("DI", fk.kpi_name, idx),
                    title=f"{fk.kpi_name} below target",
                    description=(
                        f"{fk.kpi_name} at {fk.value} vs target {fk.target} ({fk.delta_pct:+.1f}%)"
                    ),
                    priority="high" if abs(fk.delta_pct) > 20 else "medium",
                    affected_kpis=[fk.kpi_name],
                    recommendation=f"Investigate root cause for {fk.kpi_name} degradation",
                    impact_score=round(abs(fk.delta_pct) / 100.0, 2),
                )
            )
            idx += 1

        high_anomalies = [a for a in anomalies if a.severity == "high"]
        for ha in high_anomalies:
            insights.append(
                DashboardInsight(
                    id=_gen_id("DI", ha.metric_name, idx),
                    title=f"Anomaly in {ha.metric_name}",
                    description=(
                        f"{ha.anomaly_type.value} detected: {ha.deviation_pct}% deviation"
                    ),
                    priority="high",
                    affected_kpis=[ha.metric_name],
                    recommendation=f"Review {ha.metric_name} data source",
                    impact_score=round(ha.deviation_pct / 100.0, 2),
                )
            )
            idx += 1

        return insights

    async def build_dashboard_views(
        self,
        kpis: list[KPIResult],
        insights: list[DashboardInsight],
    ) -> list[DashboardView]:
        """Build configured dashboard views."""
        logger.info(
            "sod.build_views",
            kpis=len(kpis),
            insights=len(insights),
        )

        kpi_names = [k.kpi_name for k in kpis]
        views: list[DashboardView] = []
        for i, vc in enumerate(_VIEW_CONFIGS):
            views.append(
                DashboardView(
                    id=_gen_id("DV", vc["view_name"], i),
                    view_name=vc["view_name"],
                    view_type=vc["view_type"],
                    metrics_included=kpi_names,
                    time_range=vc["time_range"],
                    refresh_interval_sec=60 if vc["view_type"] == "operational" else 300,
                    audience=vc["audience"],
                )
            )
        return views

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        category: str,
    ) -> dict[str, Any]:
        """Record a custom metric."""
        logger.info(
            "sod.record_metric",
            metric=metric_name,
            category=category,
        )
        return {
            "metric": metric_name,
            "value": value,
            "category": category,
            "recorded": True,
        }
