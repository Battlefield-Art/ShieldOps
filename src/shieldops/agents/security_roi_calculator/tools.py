"""Security ROI Calculator Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    BenchmarkComparison,
    ForecastResult,
    Investment,
    InvestmentCategory,
    Outcome,
    OutcomeType,
    ROIResult,
)

logger = structlog.get_logger()

_SAMPLE_INVESTMENTS: list[dict[str, Any]] = [
    {
        "category": "tooling",
        "name": "EDR Platform",
        "annual_cost": 250000,
        "vendor": "CrowdStrike",
        "headcount_fte": 0.5,
        "contract_months": 36,
    },
    {
        "category": "tooling",
        "name": "SIEM Platform",
        "annual_cost": 180000,
        "vendor": "Splunk",
        "headcount_fte": 1.0,
        "contract_months": 24,
    },
    {
        "category": "personnel",
        "name": "SOC Team (3 analysts)",
        "annual_cost": 450000,
        "vendor": "internal",
        "headcount_fte": 3.0,
        "contract_months": 12,
    },
    {
        "category": "training",
        "name": "Security Awareness Program",
        "annual_cost": 45000,
        "vendor": "KnowBe4",
        "headcount_fte": 0.2,
        "contract_months": 12,
    },
    {
        "category": "consulting",
        "name": "Annual Pentest",
        "annual_cost": 85000,
        "vendor": "NCC Group",
        "headcount_fte": 0.0,
        "contract_months": 1,
    },
    {
        "category": "infrastructure",
        "name": "WAF + DDoS Protection",
        "annual_cost": 120000,
        "vendor": "Cloudflare",
        "headcount_fte": 0.3,
        "contract_months": 12,
    },
]

_OUTCOME_TYPES = [
    ("breach_prevention", "Prevented ransomware attack", 2500000),
    ("risk_reduction", "Reduced attack surface by 40%", 800000),
    ("compliance_savings", "Automated SOC 2 evidence collection", 150000),
    ("efficiency_gain", "Reduced MTTR from 4h to 45min", 320000),
    ("incident_reduction", "60% fewer P1 incidents", 450000),
]

_INDUSTRY_BENCHMARKS = [
    ("tooling", 35, 32),
    ("personnel", 45, 42),
    ("training", 5, 8),
    ("consulting", 8, 10),
    ("infrastructure", 7, 8),
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class SecurityROICalculatorToolkit:
    """Tools for security investment ROI calculation."""

    def __init__(
        self,
        finance_api: Any | None = None,
        benchmark_db: Any | None = None,
    ) -> None:
        self._finance_api = finance_api
        self._benchmark_db = benchmark_db

    async def collect_investments(
        self,
        tenant_id: str,
    ) -> list[Investment]:
        """Collect security investment data."""
        logger.info(
            "src.collect_investments",
            tenant_id=tenant_id,
        )

        if self._finance_api is not None:
            try:
                raw = await self._finance_api.get_investments(
                    tenant_id=tenant_id,
                )
                return [Investment(**r) for r in raw]
            except Exception:
                logger.exception("src.collect_investments.error")

        investments: list[Investment] = []
        for i, inv in enumerate(_SAMPLE_INVESTMENTS):
            noise = random.randint(-5000, 5000)  # noqa: S311
            investments.append(
                Investment(
                    id=_gen_id("INV", tenant_id, i),
                    category=InvestmentCategory(inv["category"]),
                    name=inv["name"],
                    annual_cost=inv["annual_cost"] + noise,
                    start_date="2025-01-01",
                    vendor=inv["vendor"],
                    headcount_fte=inv["headcount_fte"],
                    contract_months=inv["contract_months"],
                )
            )
        return investments

    async def measure_outcomes(
        self,
        investments: list[Investment],
    ) -> list[Outcome]:
        """Measure security outcomes linked to investments."""
        logger.info(
            "src.measure_outcomes",
            count=len(investments),
        )

        outcomes: list[Outcome] = []
        idx = 0
        for inv in investments:
            for otype, desc, base_val in _OUTCOME_TYPES:
                hit = random.random()  # noqa: S311
                if hit > 0.5:
                    val_noise = random.randint(-50000, 100000)  # noqa: S311
                    conf = round(random.uniform(0.6, 0.95), 2)  # noqa: S311
                    outcomes.append(
                        Outcome(
                            id=_gen_id("OUT", inv.id, idx),
                            outcome_type=OutcomeType(otype),
                            description=desc,
                            value_usd=base_val + val_noise,
                            measurement_period="2025-Q4",
                            confidence=conf,
                            linked_investment_id=inv.id,
                        )
                    )
                    idx += 1
        return outcomes

    async def calculate_roi(
        self,
        investments: list[Investment],
        outcomes: list[Outcome],
    ) -> list[ROIResult]:
        """Calculate ROI for each investment."""
        logger.info(
            "src.calculate_roi",
            investments=len(investments),
            outcomes=len(outcomes),
        )

        _inv_map: dict[str, Investment] = {i.id: i for i in investments}
        value_map: dict[str, float] = {}
        for o in outcomes:
            cur = value_map.get(o.linked_investment_id, 0.0)
            value_map[o.linked_investment_id] = cur + o.value_usd

        results: list[ROIResult] = []
        for i, inv in enumerate(investments):
            total_val = value_map.get(inv.id, 0.0)
            net = total_val - inv.annual_cost
            roi = round((net / max(inv.annual_cost, 1)) * 100, 1)
            payback = 12 if roi > 0 else 0
            if total_val > 0 and inv.annual_cost > 0:
                payback = max(
                    1,
                    round(inv.annual_cost / (total_val / 12)),
                )
            results.append(
                ROIResult(
                    id=_gen_id("ROI", inv.id, i),
                    investment_id=inv.id,
                    investment_name=inv.name,
                    total_cost=inv.annual_cost,
                    total_value=total_val,
                    roi_pct=roi,
                    payback_months=payback,
                    net_value=round(net, 2),
                )
            )
        return results

    async def compare_benchmarks(
        self,
        investments: list[Investment],
    ) -> list[BenchmarkComparison]:
        """Compare spending against industry benchmarks."""
        logger.info(
            "src.compare_benchmarks",
            count=len(investments),
        )

        total_spend = sum(inv.annual_cost for inv in investments)
        cat_spend: dict[str, float] = {}
        for inv in investments:
            cur = cat_spend.get(inv.category.value, 0.0)
            cat_spend[inv.category.value] = cur + inv.annual_cost

        benchmarks: list[BenchmarkComparison] = []
        for i, (cat, _org_default, ind_avg) in enumerate(_INDUSTRY_BENCHMARKS):
            org_pct = round(
                (cat_spend.get(cat, 0.0) / max(total_spend, 1)) * 100,
                1,
            )
            pctile = random.randint(25, 90)  # noqa: S311
            rec = "on track"
            if org_pct < ind_avg - 5:
                rec = "consider increasing investment"
            elif org_pct > ind_avg + 5:
                rec = "review for cost optimization"
            benchmarks.append(
                BenchmarkComparison(
                    id=_gen_id("BM", cat, i),
                    category=cat,
                    org_spend_pct=org_pct,
                    industry_avg_pct=float(ind_avg),
                    percentile=pctile,
                    recommendation=rec,
                )
            )
        return benchmarks

    async def forecast_value(
        self,
        roi_results: list[ROIResult],
    ) -> list[ForecastResult]:
        """Forecast future value of security investments."""
        logger.info(
            "src.forecast_value",
            count=len(roi_results),
        )

        periods = ["2026-Q1", "2026-Q2", "2026-Q3", "2026-Q4"]
        forecasts: list[ForecastResult] = []
        total_cost = sum(r.total_cost for r in roi_results)
        total_val = sum(r.total_value for r in roi_results)

        for i, period in enumerate(periods):
            growth = 1 + (i + 1) * 0.05
            decay = 1 + (i + 1) * 0.02
            proj_cost = round(total_cost * decay, 2)
            proj_val = round(total_val * growth, 2)
            roi = round(
                ((proj_val - proj_cost) / max(proj_cost, 1)) * 100,
                1,
            )
            forecasts.append(
                ForecastResult(
                    id=_gen_id("FC", period, i),
                    period=period,
                    projected_cost=proj_cost,
                    projected_value=proj_val,
                    projected_roi_pct=roi,
                    confidence_interval="+-15%",
                )
            )
        return forecasts

    async def record_metric(
        self,
        metric_name: str,
        value: float,
    ) -> dict[str, Any]:
        """Record an ROI metric."""
        logger.info(
            "src.record_metric",
            metric=metric_name,
            value=value,
        )
        return {"metric": metric_name, "value": value, "recorded": True}
