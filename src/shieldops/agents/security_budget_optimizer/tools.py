"""Tool functions for the Security Budget Optimizer Agent."""

from __future__ import annotations

import random
from typing import Any
from uuid import uuid4

import structlog

logger = structlog.get_logger()


class SecurityBudgetOptimizerToolkit:
    """Toolkit for security budget optimization operations."""

    def __init__(
        self,
        asset_inventory: Any | None = None,
        cost_tracker: Any | None = None,
        metrics_store: Any | None = None,
        contract_manager: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._asset_inventory = asset_inventory
        self._cost_tracker = cost_tracker
        self._metrics_store = metrics_store
        self._contract_manager = contract_manager
        self._policy_engine = policy_engine
        self._repository = repository

    async def inventory_tools(
        self,
        scan_config: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Inventory all security tools in the stack."""
        org = scan_config.get("organization", "unknown")
        logger.info(
            "sbo.inventory_tools",
            organization=org,
        )
        categories = [
            "edr",
            "siem",
            "soar",
            "iam",
            "vuln_mgmt",
            "cloud_security",
            "dlp",
        ]
        tools: list[dict[str, Any]] = []
        for cat in categories:
            count = random.randint(1, 3)  # noqa: S311
            for _i in range(count):
                tools.append(
                    {
                        "tool_id": f"t-{uuid4().hex[:8]}",
                        "name": f"{cat}-tool-{uuid4().hex[:4]}",
                        "vendor": f"vendor-{uuid4().hex[:4]}",
                        "category": cat,
                        "annual_cost": round(
                            random.uniform(10000, 500000),  # noqa: S311
                            2,
                        ),
                        "license_count": random.randint(50, 5000),  # noqa: S311
                        "utilization_pct": round(
                            random.uniform(20, 95),  # noqa: S311
                            1,
                        ),
                        "contract_end": None,
                        "metadata": {},
                    }
                )
        return tools

    async def measure_effectiveness(
        self,
        tools: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Measure effectiveness of each security tool."""
        logger.info(
            "sbo.measure_effectiveness",
            tool_count=len(tools),
        )
        scores: list[dict[str, Any]] = []
        for tool in tools:
            detection = round(
                random.uniform(40, 98),  # noqa: S311
                1,
            )
            fp_rate = round(
                random.uniform(1, 30),  # noqa: S311
                1,
            )
            cost = tool.get("annual_cost", 0)
            roi = round(
                (detection - fp_rate) / max(cost / 100000, 1),
                2,
            )
            scores.append(
                {
                    "tool_id": tool.get("tool_id", ""),
                    "detection_rate": detection,
                    "false_positive_rate": fp_rate,
                    "mttr_contribution_ms": random.randint(1000, 60000),  # noqa: S311
                    "incidents_handled": random.randint(10, 500),  # noqa: S311
                    "coverage_pct": round(
                        random.uniform(30, 90),  # noqa: S311
                        1,
                    ),
                    "roi_score": roi,
                    "reasoning": "",
                }
            )
        return scores

    async def analyze_overlap(
        self,
        tools: list[dict[str, Any]],
        scores: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Analyze overlap between security tools."""
        logger.info(
            "sbo.analyze_overlap",
            tool_count=len(tools),
        )
        _score_map = {s.get("tool_id", ""): s for s in scores}
        overlaps: list[dict[str, Any]] = []
        by_cat: dict[str, list[dict[str, Any]]] = {}
        for tool in tools:
            cat = tool.get("category", "")
            by_cat.setdefault(cat, []).append(tool)
        for _cat, cat_tools in by_cat.items():
            if len(cat_tools) < 2:
                continue
            for i in range(len(cat_tools)):
                for j in range(i + 1, len(cat_tools)):
                    overlap_pct = round(
                        random.uniform(10, 60),  # noqa: S311
                        1,
                    )
                    a_cost = cat_tools[i].get("annual_cost", 0)
                    b_cost = cat_tools[j].get("annual_cost", 0)
                    savings = round(
                        min(a_cost, b_cost) * overlap_pct / 100,
                        2,
                    )
                    overlaps.append(
                        {
                            "tool_a": cat_tools[i].get("tool_id", ""),
                            "tool_b": cat_tools[j].get("tool_id", ""),
                            "overlap_pct": overlap_pct,
                            "redundant_features": [],
                            "consolidation_savings": savings,
                            "risk_if_removed": "low" if overlap_pct > 40 else "medium",
                        }
                    )
        return overlaps

    async def optimize_budget(
        self,
        tools: list[dict[str, Any]],
        scores: list[dict[str, Any]],
        overlaps: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate optimized budget allocations."""
        logger.info(
            "sbo.optimize_budget",
            tool_count=len(tools),
            overlap_count=len(overlaps),
        )
        score_map = {s.get("tool_id", ""): s for s in scores}
        allocations: list[dict[str, Any]] = []
        for tool in tools:
            tid = tool.get("tool_id", "")
            cost = tool.get("annual_cost", 0)
            eff = score_map.get(tid, {})
            roi = eff.get("roi_score", 0)
            util = tool.get("utilization_pct", 0)
            if roi < 0.5 and util < 40:
                action = "divest"
                priority = "divest"
                rec_spend = 0.0
            elif roi > 2.0:
                action = "invest"
                priority = "high"
                rec_spend = round(cost * 1.1, 2)
            else:
                action = "maintain"
                priority = "medium"
                rec_spend = cost
            allocations.append(
                {
                    "alloc_id": f"a-{uuid4().hex[:8]}",
                    "tool_id": tid,
                    "current_spend": cost,
                    "recommended_spend": rec_spend,
                    "priority": priority,
                    "action": action,
                    "savings": round(cost - rec_spend, 2),
                    "description": "",
                }
            )
        return allocations

    async def forecast_roi(
        self,
        allocations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Forecast ROI for budget recommendations."""
        logger.info(
            "sbo.forecast_roi",
            allocation_count=len(allocations),
        )
        total_savings = sum(a.get("savings", 0) for a in allocations)
        forecasts: list[dict[str, Any]] = []
        for horizon, months in [
            ("conservative", 12),
            ("moderate", 24),
            ("aggressive", 36),
        ]:
            projected = round(
                total_savings * months / 12 * random.uniform(0.7, 1.3),  # noqa: S311
                2,
            )
            forecasts.append(
                {
                    "forecast_id": f"fc-{uuid4().hex[:8]}",
                    "scenario": horizon,
                    "projected_savings": projected,
                    "risk_delta": round(
                        random.uniform(-5, 5),  # noqa: S311
                        1,
                    ),
                    "payback_months": random.randint(3, 18),  # noqa: S311
                    "confidence": round(
                        random.uniform(0.6, 0.95),  # noqa: S311
                        2,
                    ),
                    "description": "",
                }
            )
        return forecasts

    async def record_metric(
        self,
        metric_type: str,
        value: float,
    ) -> None:
        """Record a budget optimization metric."""
        logger.info(
            "sbo.record_metric",
            metric_type=metric_type,
            value=value,
        )
