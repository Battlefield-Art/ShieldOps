"""FinOps Forecaster Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    CommitmentRecommendation,
    CommitmentType,
    CostAnomaly,
    ForecastHorizon,
    SpendForecast,
    SpendHistory,
    TrendAnalysis,
)

logger = structlog.get_logger()

_MONTHLY_PROFILES: list[dict[str, Any]] = [
    {
        "service": "EC2",
        "provider": "AWS",
        "region": "us-east-1",
        "base": 12500.0,
        "growth": 0.04,
        "seasonal": [1.0, 0.95, 1.02, 1.05, 1.1, 1.15, 1.2, 1.18, 1.1, 1.05, 1.0, 1.25],
    },
    {
        "service": "RDS",
        "provider": "AWS",
        "region": "us-east-1",
        "base": 4800.0,
        "growth": 0.03,
        "seasonal": [1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
    },
    {
        "service": "S3",
        "provider": "AWS",
        "region": "us-east-1",
        "base": 2200.0,
        "growth": 0.06,
        "seasonal": [1.0, 1.0, 1.02, 1.05, 1.08, 1.1, 1.12, 1.1, 1.08, 1.05, 1.02, 1.0],
    },
    {
        "service": "GKE",
        "provider": "GCP",
        "region": "us-central1",
        "base": 8500.0,
        "growth": 0.05,
        "seasonal": [1.0, 1.0, 1.05, 1.1, 1.15, 1.2, 1.2, 1.15, 1.1, 1.05, 1.0, 1.0],
    },
    {
        "service": "BigQuery",
        "provider": "GCP",
        "region": "us-central1",
        "base": 3200.0,
        "growth": 0.08,
        "seasonal": [1.0, 0.9, 1.0, 1.1, 1.15, 1.2, 1.1, 1.0, 1.0, 1.3, 1.2, 1.1],
    },
    {
        "service": "AKS",
        "provider": "Azure",
        "region": "eastus",
        "base": 6000.0,
        "growth": 0.04,
        "seasonal": [1.0, 1.0, 1.05, 1.1, 1.1, 1.15, 1.15, 1.1, 1.05, 1.0, 1.0, 1.0],
    },
    {
        "service": "Lambda",
        "provider": "AWS",
        "region": "us-east-1",
        "base": 1800.0,
        "growth": 0.1,
        "seasonal": [1.0, 0.9, 1.0, 1.1, 1.2, 1.3, 1.25, 1.15, 1.1, 1.05, 1.0, 1.4],
    },
    {
        "service": "CloudSQL",
        "provider": "GCP",
        "region": "us-central1",
        "base": 3800.0,
        "growth": 0.02,
        "seasonal": [1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
    },
]

_MONTHS = [
    "2025-07",
    "2025-08",
    "2025-09",
    "2025-10",
    "2025-11",
    "2025-12",
    "2026-01",
    "2026-02",
    "2026-03",
    "2026-04",
    "2026-05",
    "2026-06",
]

_HORIZON_MONTHS: dict[ForecastHorizon, int] = {
    ForecastHorizon.ONE_MONTH: 1,
    ForecastHorizon.THREE_MONTHS: 3,
    ForecastHorizon.SIX_MONTHS: 6,
    ForecastHorizon.ONE_YEAR: 12,
}


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class FinopsForecasterToolkit:
    """Tools for FinOps forecasting and commitment
    optimization."""

    def __init__(
        self,
        billing_api: Any | None = None,
        cloud_provider: Any | None = None,
    ) -> None:
        self._billing_api = billing_api
        self._cloud_provider = cloud_provider

    async def collect_history(
        self,
        tenant_id: str,
    ) -> list[SpendHistory]:
        """Collect 12 months of spending history."""
        logger.info(
            "ff.collect_history",
            tenant_id=tenant_id,
        )

        if self._billing_api is not None:
            try:
                raw = await self._billing_api.get_history(
                    tenant_id=tenant_id,
                )
                return [SpendHistory(**r) for r in raw]
            except Exception:
                logger.exception(
                    "ff.collect_history.api_error",
                )

        records: list[SpendHistory] = []
        idx = 0
        for profile in _MONTHLY_PROFILES:
            for mi, month in enumerate(_MONTHS):
                seasonal = profile["seasonal"][mi]
                growth = (1 + profile["growth"]) ** mi
                noise = random.gauss(0, 0.03)  # noqa: S311
                amount = round(
                    profile["base"] * seasonal * growth * (1 + noise),
                    2,
                )
                records.append(
                    SpendHistory(
                        id=_gen_id("SH", tenant_id, idx),
                        month=month,
                        provider=profile["provider"],
                        service=profile["service"],
                        region=profile["region"],
                        amount=max(0.0, amount),
                        tags={"env": "production"},
                    )
                )
                idx += 1
        return records

    async def analyze_trends(
        self,
        history: list[SpendHistory],
    ) -> list[TrendAnalysis]:
        """Analyze spending trends by service."""
        logger.info(
            "ff.analyze_trends",
            count=len(history),
        )

        by_svc: dict[str, list[SpendHistory]] = {}
        for h in history:
            key = f"{h.provider}:{h.service}"
            by_svc.setdefault(key, []).append(h)

        results: list[TrendAnalysis] = []
        for idx, (key, items) in enumerate(by_svc.items()):
            items.sort(key=lambda x: x.month)
            amounts = [i.amount for i in items]
            avg = sum(amounts) / max(len(amounts), 1)
            peak_idx = amounts.index(max(amounts))
            trough_idx = amounts.index(min(amounts))

            if len(amounts) >= 2 and amounts[0] > 0:
                total_growth = (amounts[-1] - amounts[0]) / amounts[0] * 100
            else:
                total_growth = 0.0

            direction = "increasing"
            if total_growth < -5:
                direction = "decreasing"
            elif abs(total_growth) <= 5:
                direction = "stable"

            variance = sum((a - avg) ** 2 for a in amounts) / max(len(amounts), 1)
            cv = (variance**0.5) / max(avg, 1.0)
            seasonality = "none"
            if cv > 0.15:
                seasonality = "high"
            elif cv > 0.07:
                seasonality = "moderate"

            parts = key.split(":", 1)
            results.append(
                TrendAnalysis(
                    id=_gen_id("TA", key, idx),
                    service=parts[1] if len(parts) > 1 else key,
                    provider=parts[0],
                    direction=direction,
                    growth_rate_pct=round(
                        total_growth,
                        1,
                    ),
                    seasonality=seasonality,
                    avg_monthly=round(avg, 2),
                    peak_month=(items[peak_idx].month if items else ""),
                    trough_month=(items[trough_idx].month if items else ""),
                )
            )
        return results

    async def forecast_spend(
        self,
        trends: list[TrendAnalysis],
    ) -> list[SpendForecast]:
        """Forecast spending for the next quarter."""
        logger.info(
            "ff.forecast_spend",
            count=len(trends),
        )

        horizon = ForecastHorizon.THREE_MONTHS
        months = _HORIZON_MONTHS[horizon]
        forecasts: list[SpendForecast] = []

        for idx, trend in enumerate(trends):
            monthly_growth = 1 + trend.growth_rate_pct / 100 / 12
            projected = round(
                trend.avg_monthly * (monthly_growth**months),
                2,
            )
            total = round(projected * months, 2)
            budget = round(
                trend.avg_monthly * months * 1.1,
                2,
            )
            overrun = total > budget
            overrun_amt = round(
                max(0.0, total - budget),
                2,
            )

            confidence = 85.0
            if trend.seasonality == "high":
                confidence = 70.0
            elif trend.seasonality == "moderate":
                confidence = 78.0

            forecasts.append(
                SpendForecast(
                    id=_gen_id("SF", trend.id, idx),
                    service=trend.service,
                    provider=trend.provider,
                    horizon=horizon,
                    projected_monthly=projected,
                    projected_total=total,
                    confidence_pct=confidence,
                    budget_limit=budget,
                    overrun_risk=overrun,
                    overrun_amount=overrun_amt,
                )
            )
        return forecasts

    async def detect_anomalies(
        self,
        history: list[SpendHistory],
        forecasts: list[SpendForecast],
    ) -> list[CostAnomaly]:
        """Detect anomalies by comparing history to
        forecasted norms."""
        logger.info(
            "ff.detect_anomalies",
            history=len(history),
            forecasts=len(forecasts),
        )

        svc_avg: dict[str, float] = {}
        svc_items: dict[str, list[SpendHistory]] = {}
        for h in history:
            key = f"{h.provider}:{h.service}"
            svc_items.setdefault(key, []).append(h)

        for key, items in svc_items.items():
            amounts = [i.amount for i in items]
            svc_avg[key] = sum(amounts) / max(len(amounts), 1)

        anomalies: list[CostAnomaly] = []
        idx = 0
        for key, items in svc_items.items():
            avg = svc_avg.get(key, 0.0)
            if avg <= 0:
                continue
            for item in items:
                dev = (item.amount - avg) / avg * 100
                if abs(dev) > 25.0:
                    severity = "low"
                    if abs(dev) > 50:
                        severity = "critical"
                    elif abs(dev) > 35:
                        severity = "high"
                    elif abs(dev) > 25:
                        severity = "medium"

                    parts = key.split(":", 1)
                    anomalies.append(
                        CostAnomaly(
                            id=_gen_id(
                                "CA",
                                key,
                                idx,
                            ),
                            service=(parts[1] if len(parts) > 1 else key),
                            provider=parts[0],
                            month=item.month,
                            expected_amount=round(
                                avg,
                                2,
                            ),
                            actual_amount=item.amount,
                            deviation_pct=round(
                                dev,
                                1,
                            ),
                            severity=severity,
                            explanation=(
                                f"{item.service} spend "
                                f"deviated {dev:+.1f}% "
                                f"from avg in "
                                f"{item.month}"
                            ),
                        )
                    )
                    idx += 1
        return anomalies

    async def recommend_commitments(
        self,
        forecasts: list[SpendForecast],
        trends: list[TrendAnalysis],
    ) -> list[CommitmentRecommendation]:
        """Recommend RI/savings plan purchases."""
        logger.info(
            "ff.recommend_commitments",
            forecasts=len(forecasts),
        )

        trend_map: dict[str, TrendAnalysis] = {f"{t.provider}:{t.service}": t for t in trends}

        recs: list[CommitmentRecommendation] = []
        for idx, fc in enumerate(forecasts):
            key = f"{fc.provider}:{fc.service}"
            trend = trend_map.get(key)

            if fc.projected_monthly < 2000:
                continue

            if trend and trend.direction == "decreasing":
                continue

            ri_discount = 0.35
            sp_discount = 0.25

            if trend and trend.seasonality in (
                "none",
                "moderate",
            ):
                ctype = CommitmentType.RESERVED_INSTANCE
                discount = ri_discount
                term = 12
                risk = "low"
            else:
                ctype = CommitmentType.SAVINGS_PLAN
                discount = sp_discount
                term = 12
                risk = "medium"

            monthly_save = round(
                fc.projected_monthly * discount,
                2,
            )
            annual_save = round(monthly_save * 12, 2)
            upfront = round(monthly_save * 3, 2)
            break_even = max(
                1,
                int(upfront / max(monthly_save, 1)),
            )

            confidence = fc.confidence_pct * 0.9
            if trend and trend.direction == "stable":
                confidence = min(
                    95.0,
                    confidence + 5,
                )

            recs.append(
                CommitmentRecommendation(
                    id=_gen_id("CR", fc.id, idx),
                    service=fc.service,
                    provider=fc.provider,
                    commitment_type=ctype,
                    term_months=term,
                    upfront_cost=upfront,
                    monthly_savings=monthly_save,
                    annual_savings=annual_save,
                    break_even_months=break_even,
                    confidence_pct=round(
                        confidence,
                        1,
                    ),
                    risk=risk,
                )
            )
        return recs
