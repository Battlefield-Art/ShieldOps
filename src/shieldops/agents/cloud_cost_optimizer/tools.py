"""Cloud Cost Optimizer Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    BillingRecord,
    CostCategory,
    OptimizationResult,
    SavingsPotential,
    SavingsRecommendation,
    SpendingAnalysis,
    WasteItem,
)

logger = structlog.get_logger()

_BILLING_PROFILES: list[dict[str, Any]] = [
    {
        "resource_id": "i-prod-api-01",
        "category": CostCategory.COMPUTE,
        "provider": "AWS",
        "region": "us-east-1",
        "daily": 45.0,
        "util": 72.0,
    },
    {
        "resource_id": "i-prod-api-02",
        "category": CostCategory.COMPUTE,
        "provider": "AWS",
        "region": "us-east-1",
        "daily": 45.0,
        "util": 12.0,
    },
    {
        "resource_id": "rds-prod-main",
        "category": CostCategory.DATABASE,
        "provider": "AWS",
        "region": "us-east-1",
        "daily": 85.0,
        "util": 55.0,
    },
    {
        "resource_id": "s3-logs-archive",
        "category": CostCategory.STORAGE,
        "provider": "AWS",
        "region": "us-east-1",
        "daily": 8.0,
        "util": 15.0,
    },
    {
        "resource_id": "nat-gateway-01",
        "category": CostCategory.NETWORK,
        "provider": "AWS",
        "region": "us-east-1",
        "daily": 32.0,
        "util": 40.0,
    },
    {
        "resource_id": "lambda-etl-pipeline",
        "category": CostCategory.SERVERLESS,
        "provider": "AWS",
        "region": "us-east-1",
        "daily": 18.0,
        "util": 65.0,
    },
    {
        "resource_id": "license-datadog",
        "category": CostCategory.LICENSING,
        "provider": "Datadog",
        "region": "global",
        "daily": 25.0,
        "util": 80.0,
    },
    {
        "resource_id": "gke-cluster-prod",
        "category": CostCategory.COMPUTE,
        "provider": "GCP",
        "region": "us-central1",
        "daily": 120.0,
        "util": 58.0,
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class CloudCostOptimizerToolkit:
    """Tools for cloud cost optimization."""

    def __init__(
        self,
        billing_api: Any | None = None,
        cloud_provider: Any | None = None,
    ) -> None:
        self._billing_api = billing_api
        self._cloud_provider = cloud_provider

    async def collect_billing(
        self,
        tenant_id: str,
    ) -> list[BillingRecord]:
        """Collect billing records from cloud providers."""
        logger.info(
            "cco.collect_billing",
            tenant_id=tenant_id,
        )

        if self._billing_api is not None:
            try:
                raw = await self._billing_api.get_billing(
                    tenant_id=tenant_id,
                )
                return [BillingRecord(**r) for r in raw]
            except Exception:
                logger.exception("cco.collect_billing.error")

        records: list[BillingRecord] = []
        for i, p in enumerate(_BILLING_PROFILES):
            noise = random.gauss(0, 3.0)  # noqa: S311
            daily = round(max(0.0, p["daily"] + noise), 2)
            records.append(
                BillingRecord(
                    id=_gen_id("BR", tenant_id, i),
                    resource_id=p["resource_id"],
                    category=p["category"],
                    provider=p["provider"],
                    region=p["region"],
                    daily_cost=daily,
                    monthly_cost=round(daily * 30, 2),
                    utilization_pct=p["util"],
                    tags={"env": "production"},
                )
            )
        return records

    async def analyze_spending(
        self,
        records: list[BillingRecord],
    ) -> list[SpendingAnalysis]:
        """Analyze spending by category."""
        logger.info(
            "cco.analyze_spending",
            count=len(records),
        )

        by_cat: dict[CostCategory, list[BillingRecord]] = {}
        for r in records:
            by_cat.setdefault(r.category, []).append(r)

        results: list[SpendingAnalysis] = []
        for cat, items in by_cat.items():
            total = sum(i.monthly_cost for i in items)
            results.append(
                SpendingAnalysis(
                    category=cat,
                    total_monthly=round(total, 2),
                    trend=random.choice(  # noqa: S311
                        ["increasing", "stable", "decreasing"],
                    ),
                    budget_pct=round(
                        total / max(total * 1.2, 1.0) * 100,
                        1,
                    ),
                    top_resources=[i.resource_id for i in items[:3]],
                )
            )
        return results

    async def identify_waste(
        self,
        records: list[BillingRecord],
    ) -> list[WasteItem]:
        """Identify wasted resources."""
        logger.info(
            "cco.identify_waste",
            count=len(records),
        )

        waste: list[WasteItem] = []
        idx = 0
        for r in records:
            if r.utilization_pct < 15.0:
                waste.append(
                    WasteItem(
                        id=_gen_id("WI", r.id, idx),
                        resource_id=r.resource_id,
                        category=r.category,
                        waste_type="idle_resource",
                        monthly_waste=round(
                            r.monthly_cost * 0.9,
                            2,
                        ),
                        utilization_pct=r.utilization_pct,
                        recommendation=(f"Terminate {r.resource_id}"),
                        savings=SavingsPotential.HIGH,
                    )
                )
                idx += 1
            elif r.utilization_pct < 35.0:
                waste.append(
                    WasteItem(
                        id=_gen_id("WI", r.id, idx),
                        resource_id=r.resource_id,
                        category=r.category,
                        waste_type="oversized",
                        monthly_waste=round(
                            r.monthly_cost * 0.4,
                            2,
                        ),
                        utilization_pct=r.utilization_pct,
                        recommendation=(f"Rightsize {r.resource_id}"),
                        savings=SavingsPotential.MEDIUM,
                    )
                )
                idx += 1
        return waste

    async def recommend_savings(
        self,
        waste: list[WasteItem],
        analysis: list[SpendingAnalysis],
    ) -> list[SavingsRecommendation]:
        """Generate savings recommendations."""
        logger.info(
            "cco.recommend_savings",
            waste=len(waste),
        )

        recs: list[SavingsRecommendation] = []
        for i, w in enumerate(waste):
            recs.append(
                SavingsRecommendation(
                    id=_gen_id("SR", w.id, i),
                    resource_id=w.resource_id,
                    action=w.waste_type,
                    description=w.recommendation,
                    estimated_monthly_savings=w.monthly_waste,
                    auto_executable=(w.waste_type == "idle_resource"),
                    priority=("high" if w.savings == SavingsPotential.HIGH else "medium"),
                    risk="low",
                )
            )
        return recs

    async def implement_optimizations(
        self,
        recs: list[SavingsRecommendation],
    ) -> list[OptimizationResult]:
        """Implement approved optimizations."""
        logger.info(
            "cco.implement",
            count=len(recs),
        )

        results: list[OptimizationResult] = []
        for i, r in enumerate(recs):
            if not r.auto_executable:
                results.append(
                    OptimizationResult(
                        id=_gen_id("OPT", r.id, i),
                        recommendation_id=r.id,
                        status="pending_approval",
                        actual_savings=0.0,
                        rollback_available=True,
                    )
                )
            else:
                results.append(
                    OptimizationResult(
                        id=_gen_id("OPT", r.id, i),
                        recommendation_id=r.id,
                        status="applied",
                        actual_savings=round(
                            r.estimated_monthly_savings * 0.95,
                            2,
                        ),
                        rollback_available=True,
                    )
                )
        return results
