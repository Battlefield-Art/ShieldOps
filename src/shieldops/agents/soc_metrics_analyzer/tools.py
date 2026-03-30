"""Tool functions for the SOC Metrics Analyzer Agent."""

from __future__ import annotations

import random
from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger()

# Industry benchmark reference data
_INDUSTRY_BENCHMARKS: dict[str, dict[str, float]] = {
    "mttd_hours": {
        "p25": 2.5,
        "median": 24.0,
        "p75": 168.0,
    },
    "mttr_hours": {
        "p25": 8.0,
        "median": 73.0,
        "p75": 287.0,
    },
    "false_positive_rate": {
        "p25": 18.0,
        "median": 45.0,
        "p75": 65.0,
    },
    "alert_volume_daily": {
        "p25": 350.0,
        "median": 2500.0,
        "p75": 11000.0,
    },
    "analyst_utilization_pct": {
        "p25": 55.0,
        "median": 72.0,
        "p75": 91.0,
    },
    "detection_coverage_pct": {
        "p25": 55.0,
        "median": 72.0,
        "p75": 88.0,
    },
    "escalation_rate_pct": {
        "p25": 5.0,
        "median": 15.0,
        "p75": 30.0,
    },
    "automation_rate_pct": {
        "p25": 10.0,
        "median": 30.0,
        "p75": 60.0,
    },
}


class SOCMetricsAnalyzerToolkit:
    """Toolkit for collecting and analyzing SOC metrics."""

    def __init__(
        self,
        siem_client: Any | None = None,
        soar_client: Any | None = None,
        ticketing_client: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._siem = siem_client
        self._soar = soar_client
        self._ticketing = ticketing_client
        self._metrics_store = metrics_store
        self._repository = repository

    async def collect_detection_metrics(
        self,
        time_range_days: int = 30,
    ) -> list[dict[str, Any]]:
        """Collect detection-related SOC metrics."""
        logger.info(
            "sma.collect_detection",
            time_range_days=time_range_days,
        )
        if self._siem:
            return await self._siem.get_detection_metrics(
                days=time_range_days,
            )
        # Realistic simulated data
        return [
            {
                "metric_id": f"det-{uuid4().hex[:8]}",
                "name": "mttd_hours",
                "category": "detection",
                "value": round(
                    random.uniform(1.5, 36.0),  # noqa: S311
                    2,
                ),
                "unit": "hours",
                "source": "siem",
            },
            {
                "metric_id": f"det-{uuid4().hex[:8]}",
                "name": "detection_coverage_pct",
                "category": "detection",
                "value": round(
                    random.uniform(55.0, 92.0),  # noqa: S311
                    1,
                ),
                "unit": "percent",
                "source": "siem",
            },
            {
                "metric_id": f"det-{uuid4().hex[:8]}",
                "name": "false_positive_rate",
                "category": "detection",
                "value": round(
                    random.uniform(15.0, 65.0),  # noqa: S311
                    1,
                ),
                "unit": "percent",
                "source": "siem",
            },
            {
                "metric_id": f"det-{uuid4().hex[:8]}",
                "name": "alert_volume_daily",
                "category": "detection",
                "value": round(
                    random.uniform(200.0, 15000.0),  # noqa: S311
                    0,
                ),
                "unit": "alerts/day",
                "source": "siem",
            },
        ]

    async def collect_response_metrics(
        self,
        time_range_days: int = 30,
    ) -> list[dict[str, Any]]:
        """Collect response-related SOC metrics."""
        logger.info(
            "sma.collect_response",
            time_range_days=time_range_days,
        )
        if self._soar:
            return await self._soar.get_response_metrics(
                days=time_range_days,
            )
        return [
            {
                "metric_id": f"resp-{uuid4().hex[:8]}",
                "name": "mttr_hours",
                "category": "response",
                "value": round(
                    random.uniform(4.0, 120.0),  # noqa: S311
                    2,
                ),
                "unit": "hours",
                "source": "soar",
            },
            {
                "metric_id": f"resp-{uuid4().hex[:8]}",
                "name": "mtta_hours",
                "category": "response",
                "value": round(
                    random.uniform(0.5, 8.0),  # noqa: S311
                    2,
                ),
                "unit": "hours",
                "source": "soar",
            },
            {
                "metric_id": f"resp-{uuid4().hex[:8]}",
                "name": "escalation_rate_pct",
                "category": "response",
                "value": round(
                    random.uniform(5.0, 35.0),  # noqa: S311
                    1,
                ),
                "unit": "percent",
                "source": "soar",
            },
        ]

    async def collect_efficiency_metrics(
        self,
        time_range_days: int = 30,
    ) -> list[dict[str, Any]]:
        """Collect analyst efficiency metrics."""
        logger.info(
            "sma.collect_efficiency",
            time_range_days=time_range_days,
        )
        if self._ticketing:
            return await self._ticketing.get_efficiency_metrics(
                days=time_range_days,
            )
        return [
            {
                "metric_id": f"eff-{uuid4().hex[:8]}",
                "name": "analyst_utilization_pct",
                "category": "efficiency",
                "value": round(
                    random.uniform(50.0, 95.0),  # noqa: S311
                    1,
                ),
                "unit": "percent",
                "source": "ticketing",
            },
            {
                "metric_id": f"eff-{uuid4().hex[:8]}",
                "name": "automation_rate_pct",
                "category": "efficiency",
                "value": round(
                    random.uniform(8.0, 65.0),  # noqa: S311
                    1,
                ),
                "unit": "percent",
                "source": "soar",
            },
            {
                "metric_id": f"eff-{uuid4().hex[:8]}",
                "name": "tickets_per_analyst_day",
                "category": "efficiency",
                "value": round(
                    random.uniform(8.0, 45.0),  # noqa: S311
                    0,
                ),
                "unit": "tickets/analyst/day",
                "source": "ticketing",
            },
            {
                "metric_id": f"eff-{uuid4().hex[:8]}",
                "name": "mean_triage_minutes",
                "category": "efficiency",
                "value": round(
                    random.uniform(3.0, 30.0),  # noqa: S311
                    1,
                ),
                "unit": "minutes",
                "source": "ticketing",
            },
        ]

    async def get_historical_metrics(
        self,
        metric_name: str,
        periods: int = 6,
    ) -> list[dict[str, Any]]:
        """Retrieve historical values for trend analysis."""
        logger.info(
            "sma.get_historical",
            metric_name=metric_name,
            periods=periods,
        )
        if self._metrics_store:
            return await self._metrics_store.get_history(
                metric_name,
                periods=periods,
            )
        # Generate plausible historical series
        base = random.uniform(20.0, 80.0)  # noqa: S311
        drift = random.uniform(-2.0, 2.0)  # noqa: S311
        return [
            {
                "period": i,
                "value": round(
                    base
                    + drift * i  # noqa: S311
                    + random.uniform(-5.0, 5.0),  # noqa: S311
                    2,
                ),
            }
            for i in range(periods)
        ]

    async def get_industry_benchmarks(
        self,
        metric_name: str,
    ) -> dict[str, float]:
        """Return industry benchmark values for a metric."""
        logger.info(
            "sma.get_benchmark",
            metric_name=metric_name,
        )
        return _INDUSTRY_BENCHMARKS.get(
            metric_name,
            {"p25": 0.0, "median": 0.0, "p75": 0.0},
        )

    async def compute_percentile(
        self,
        metric_name: str,
        value: float,
    ) -> float:
        """Compute percentile rank against benchmarks."""
        bench = await self.get_industry_benchmarks(metric_name)
        p25 = bench.get("p25", 0.0)
        median = bench.get("median", 0.0)
        p75 = bench.get("p75", 0.0)
        if p75 == p25:
            return 50.0
        # Lower is better for time/rate metrics
        lower_better = metric_name in {
            "mttd_hours",
            "mttr_hours",
            "false_positive_rate",
            "alert_volume_daily",
            "escalation_rate_pct",
            "mean_triage_minutes",
        }
        if lower_better:
            if value <= p25:
                return round(
                    min(95.0, 75.0 + 20.0 * (p25 - value) / max(p25, 1.0)),
                    1,
                )
            if value <= median:
                return round(
                    50.0 + 25.0 * (median - value) / max(median - p25, 1.0),
                    1,
                )
            if value <= p75:
                return round(
                    25.0 + 25.0 * (p75 - value) / max(p75 - median, 1.0),
                    1,
                )
            return round(
                max(5.0, 25.0 * (1.0 - (value - p75) / max(p75, 1.0))),
                1,
            )
        # Higher is better
        if value >= p75:
            return round(
                min(95.0, 75.0 + 20.0 * (value - p75) / max(p75, 1.0)),
                1,
            )
        if value >= median:
            return round(
                50.0 + 25.0 * (value - median) / max(p75 - median, 1.0),
                1,
            )
        if value >= p25:
            return round(
                25.0 + 25.0 * (value - p25) / max(median - p25, 1.0),
                1,
            )
        return round(
            max(5.0, 25.0 * value / max(p25, 1.0)),
            1,
        )

    async def store_analysis(
        self,
        analysis: dict[str, Any],
    ) -> None:
        """Persist analysis results."""
        logger.info(
            "sma.store_analysis",
            score=analysis.get("overall_score", 0),
        )
        if self._repository:
            await self._repository.save(analysis)
