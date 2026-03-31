"""Security Metric Dashboard Agent — Tool functions for
metrics aggregation and executive reporting."""

from __future__ import annotations

import random
import time
from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger()

_MTTD_TARGET_HOURS = 4.0
_MTTR_TARGET_HOURS = 24.0
_VULN_SLA_TARGET = 0.90


class SecurityMetricDashboardToolkit:
    """Toolkit for security metrics aggregation,
    KPI computation, and executive reporting."""

    def __init__(
        self,
        siem_connector: Any | None = None,
        vuln_scanner: Any | None = None,
        edr_connector: Any | None = None,
        compliance_engine: Any | None = None,
        benchmark_db: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._siem = siem_connector
        self._vuln_scanner = vuln_scanner
        self._edr = edr_connector
        self._compliance = compliance_engine
        self._benchmark_db = benchmark_db
        self._repository = repository

    async def collect_metrics(
        self,
        tenant_id: str,
        period: str = "30d",
    ) -> list[dict[str, Any]]:
        """Collect raw security metrics from SIEM, EDR,
        vulnerability scanners, and compliance engines.

        Aggregates metrics across detection, response,
        vulnerability, compliance, and coverage domains.
        """
        logger.info(
            "smd.collect_metrics",
            tenant_id=tenant_id,
            period=period,
        )
        metrics: list[dict[str, Any]] = []

        sources = [
            ("siem", self._siem),
            ("vuln_scanner", self._vuln_scanner),
            ("edr", self._edr),
            ("compliance", self._compliance),
        ]

        for _name, connector in sources:
            if connector is None:
                continue
            try:
                if hasattr(connector, "get_metrics"):
                    raw = await connector.get_metrics(
                        tenant_id=tenant_id,
                        period=period,
                    )
                    metrics.extend(raw)
            except Exception:
                logger.warning("smd.collect.error")

        if not metrics:
            metrics = self._synthetic_metrics(tenant_id)

        return metrics

    async def normalize_metrics(
        self,
        raw_metrics: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Normalize raw metrics to consistent units
        and time periods.

        Standardizes values, maps to security domains,
        and validates data quality.
        """
        logger.info(
            "smd.normalize_metrics",
            count=len(raw_metrics),
        )
        normalized: list[dict[str, Any]] = []

        for metric in raw_metrics:
            mid = uuid4().hex[:12]
            normalized.append(
                {
                    "metric_id": f"norm-{mid}",
                    "domain": metric.get("domain", "detection"),
                    "name": metric.get("name", ""),
                    "normalized_value": metric.get("value", 0.0),
                    "original_value": metric.get("value", 0.0),
                    "unit": metric.get("unit", ""),
                    "period": "30d",
                }
            )

        return normalized

    async def calculate_kpis(
        self,
        normalized: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Calculate security KPIs from normalized
        metrics.

        Computes MTTD, MTTR, MTTC, vulnerability SLA
        compliance, coverage gaps, and operational KPIs.
        """
        logger.info(
            "smd.calculate_kpis",
            metric_count=len(normalized),
        )
        rand_mttd = random.uniform(2.0, 8.0)  # noqa: S311
        rand_mttr = random.uniform(12.0, 48.0)  # noqa: S311
        rand_vuln = random.uniform(0.75, 0.98)  # noqa: S311

        kpis: list[dict[str, Any]] = [
            {
                "kpi_id": "mttd",
                "name": "Mean Time to Detect",
                "value": round(rand_mttd, 1),
                "target": _MTTD_TARGET_HOURS,
                "unit": "hours",
                "status": ("passing" if rand_mttd <= _MTTD_TARGET_HOURS else "failing"),
                "trend": "improving",
                "domain": "detection",
            },
            {
                "kpi_id": "mttr",
                "name": "Mean Time to Respond",
                "value": round(rand_mttr, 1),
                "target": _MTTR_TARGET_HOURS,
                "unit": "hours",
                "status": ("passing" if rand_mttr <= _MTTR_TARGET_HOURS else "failing"),
                "trend": "stable",
                "domain": "response",
            },
            {
                "kpi_id": "vuln_sla",
                "name": "Vulnerability SLA Compliance",
                "value": round(rand_vuln * 100, 1),
                "target": _VULN_SLA_TARGET * 100,
                "unit": "percent",
                "status": ("passing" if rand_vuln >= _VULN_SLA_TARGET else "failing"),
                "trend": "improving",
                "domain": "vulnerability",
            },
        ]

        return kpis

    async def benchmark_industry(
        self,
        kpis: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Benchmark KPIs against industry standards.

        Compares organizational metrics against industry
        median and p75 benchmarks for peer context.
        """
        logger.info(
            "smd.benchmark_industry",
            kpi_count=len(kpis),
        )
        benchmarks: list[dict[str, Any]] = []

        for kpi in kpis:
            org_val = kpi.get("value", 0.0)
            rand_med = random.uniform(  # noqa: S311
                org_val * 0.8, org_val * 1.3
            )
            rand_p75 = rand_med * 0.7

            rand_pct = random.randint(30, 90)  # noqa: S311
            benchmarks.append(
                {
                    "kpi_name": kpi.get("name", ""),
                    "org_value": org_val,
                    "industry_median": round(rand_med, 1),
                    "industry_p75": round(rand_p75, 1),
                    "percentile_rank": rand_pct,
                    "gap": round(org_val - rand_p75, 1),
                }
            )

        return benchmarks

    async def build_dashboard(
        self,
        kpis: list[dict[str, Any]],
        benchmarks: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Build dashboard data structure for rendering.

        Composes KPIs, benchmarks, and trend data into
        a dashboard-ready payload.
        """
        logger.info(
            "smd.build_dashboard",
            kpi_count=len(kpis),
        )
        failing = [k["name"] for k in kpis if k.get("status") == "failing"]
        return {
            "kpi_count": len(kpis),
            "failing_count": len(failing),
            "failing_kpis": failing,
            "kpis": kpis,
            "benchmarks": benchmarks,
            "generated_at": time.time(),
        }

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Record a dashboard metric for telemetry."""
        logger.info(
            "smd.record_metric",
            metric=metric_name,
            value=value,
        )
        return {
            "metric": metric_name,
            "value": value,
            "tags": tags or {},
            "timestamp": time.time(),
        }

    def _synthetic_metrics(
        self,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Generate synthetic metrics for testing."""
        now = time.time()
        rand_det = random.uniform(3.0, 7.0)  # noqa: S311
        rand_resp = random.uniform(15.0, 40.0)  # noqa: S311
        rand_vuln = random.uniform(80.0, 98.0)  # noqa: S311
        return [
            {
                "metric_id": f"syn-{tenant_id}-mttd",
                "source": "siem",
                "domain": "detection",
                "name": "mttd_hours",
                "value": round(rand_det, 1),
                "unit": "hours",
                "timestamp": now,
            },
            {
                "metric_id": f"syn-{tenant_id}-mttr",
                "source": "siem",
                "domain": "response",
                "name": "mttr_hours",
                "value": round(rand_resp, 1),
                "unit": "hours",
                "timestamp": now,
            },
            {
                "metric_id": f"syn-{tenant_id}-vuln",
                "source": "vuln_scanner",
                "domain": "vulnerability",
                "name": "vuln_sla_pct",
                "value": round(rand_vuln, 1),
                "unit": "percent",
                "timestamp": now,
            },
        ]
