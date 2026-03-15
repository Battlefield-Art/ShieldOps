"""TelemetryCostOptimizerEngine — optimize overall telemetry pipeline cost,
identify waste, recommend reductions, track savings."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CostCategory(StrEnum):
    COLLECTION = "collection"
    PROCESSING = "processing"
    STORAGE = "storage"
    EXPORT = "export"


class OptimizationStrategy(StrEnum):
    DROP_LOW_VALUE = "drop_low_value"
    AGGREGATE = "aggregate"
    DOWNSAMPLE = "downsample"
    COMPRESS = "compress"


class SavingsStatus(StrEnum):
    PROJECTED = "projected"
    REALIZED = "realized"
    MISSED = "missed"
    REVERTED = "reverted"


# --- Models ---


class TelemetryCostRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_name: str = ""
    cost_category: CostCategory = CostCategory.STORAGE
    optimization_strategy: OptimizationStrategy = OptimizationStrategy.DOWNSAMPLE
    savings_status: SavingsStatus = SavingsStatus.PROJECTED
    cost_usd: float = 0.0
    projected_savings_usd: float = 0.0
    realized_savings_usd: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class TelemetryCostAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_name: str = ""
    total_cost_usd: float = 0.0
    avg_cost_usd: float = 0.0
    total_projected_savings_usd: float = 0.0
    total_realized_savings_usd: float = 0.0
    optimization_strategy: OptimizationStrategy = OptimizationStrategy.DOWNSAMPLE
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TelemetryCostReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    total_cost_usd: float = 0.0
    total_projected_savings_usd: float = 0.0
    total_realized_savings_usd: float = 0.0
    by_cost_category: dict[str, int] = Field(default_factory=dict)
    by_optimization_strategy: dict[str, int] = Field(default_factory=dict)
    by_savings_status: dict[str, int] = Field(default_factory=dict)
    top_cost_pipelines: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class TelemetryCostOptimizerEngine:
    """Optimize overall telemetry pipeline cost — identify waste, recommend
    reductions, track savings."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 1000.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[TelemetryCostRecord] = []
        self._analyses: list[TelemetryCostAnalysis] = []
        logger.info(
            "telemetry.cost.optimizer.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        pipeline_name: str,
        cost_category: CostCategory = CostCategory.STORAGE,
        optimization_strategy: OptimizationStrategy = OptimizationStrategy.DOWNSAMPLE,
        savings_status: SavingsStatus = SavingsStatus.PROJECTED,
        cost_usd: float = 0.0,
        projected_savings_usd: float = 0.0,
        realized_savings_usd: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> TelemetryCostRecord:
        record = TelemetryCostRecord(
            pipeline_name=pipeline_name,
            cost_category=cost_category,
            optimization_strategy=optimization_strategy,
            savings_status=savings_status,
            cost_usd=cost_usd,
            projected_savings_usd=projected_savings_usd,
            realized_savings_usd=realized_savings_usd,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "telemetry.cost.optimizer.record_added",
            record_id=record.id,
            pipeline_name=pipeline_name,
            cost_category=cost_category.value,
        )
        return record

    def get_record(self, record_id: str) -> TelemetryCostRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        pipeline_name: str | None = None,
        cost_category: CostCategory | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[TelemetryCostRecord]:
        results = list(self._records)
        if pipeline_name is not None:
            results = [r for r in results if r.pipeline_name == pipeline_name]
        if cost_category is not None:
            results = [r for r in results if r.cost_category == cost_category]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, pipeline_name: str) -> TelemetryCostAnalysis | None:
        records = [r for r in self._records if r.pipeline_name == pipeline_name]
        if not records:
            return None
        costs = [r.cost_usd for r in records]
        total_cost = round(sum(costs), 2)
        avg_cost = round(total_cost / len(costs), 2)
        total_projected = round(sum(r.projected_savings_usd for r in records), 2)
        total_realized = round(sum(r.realized_savings_usd for r in records), 2)
        # Pick most common strategy
        strategy_counts: dict[OptimizationStrategy, int] = {}
        for r in records:
            strategy_counts[r.optimization_strategy] = (
                strategy_counts.get(r.optimization_strategy, 0) + 1
            )
        best_strategy = max(strategy_counts, key=lambda k: strategy_counts[k])
        analysis = TelemetryCostAnalysis(
            pipeline_name=pipeline_name,
            total_cost_usd=total_cost,
            avg_cost_usd=avg_cost,
            total_projected_savings_usd=total_projected,
            total_realized_savings_usd=total_realized,
            optimization_strategy=best_strategy,
            description=(
                f"Cost analysis for {pipeline_name}: total=${total_cost}, "
                f"projected savings=${total_projected}, realized=${total_realized}"
            ),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "telemetry.cost.optimizer.processed",
            pipeline_name=pipeline_name,
            total_cost_usd=total_cost,
            strategy=best_strategy.value,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_cost_reduction_opportunities(self) -> list[dict[str, Any]]:
        """Find waste in telemetry pipeline."""
        by_pipeline: dict[str, list[TelemetryCostRecord]] = {}
        for r in self._records:
            by_pipeline.setdefault(r.pipeline_name, []).append(r)
        results: list[dict[str, Any]] = []
        for name, recs in by_pipeline.items():
            total_cost = sum(r.cost_usd for r in recs)
            avg_cost = total_cost / len(recs)
            realized = sum(r.realized_savings_usd for r in recs)
            projected = sum(r.projected_savings_usd for r in recs)
            unrealized = max(0.0, projected - realized)
            if total_cost > self._threshold or unrealized > 0:
                results.append(
                    {
                        "pipeline_name": name,
                        "total_cost_usd": round(total_cost, 2),
                        "avg_cost_usd": round(avg_cost, 2),
                        "unrealized_savings_usd": round(unrealized, 2),
                        "record_count": len(recs),
                    }
                )
        results.sort(key=lambda x: x["total_cost_usd"], reverse=True)
        return results

    def simulate_optimization(self, strategy: OptimizationStrategy) -> dict[str, Any]:
        """Project savings from a specific optimization strategy."""
        if not self._records:
            return {"strategy": strategy.value, "status": "no_data"}
        total_cost = sum(r.cost_usd for r in self._records)
        # Estimate reduction factors per strategy
        reduction_factors = {
            OptimizationStrategy.DROP_LOW_VALUE: 0.30,
            OptimizationStrategy.AGGREGATE: 0.20,
            OptimizationStrategy.DOWNSAMPLE: 0.40,
            OptimizationStrategy.COMPRESS: 0.15,
        }
        factor = reduction_factors.get(strategy, 0.20)
        projected_savings = round(total_cost * factor, 2)
        return {
            "strategy": strategy.value,
            "total_current_cost_usd": round(total_cost, 2),
            "reduction_factor": factor,
            "projected_daily_savings_usd": projected_savings,
            "projected_monthly_savings_usd": round(projected_savings * 30, 2),
            "affected_records": len(self._records),
        }

    def track_realized_savings(self) -> dict[str, Any]:
        """Compare projected vs. actual savings."""
        if not self._records:
            return {"status": "no_data"}
        total_projected = sum(r.projected_savings_usd for r in self._records)
        total_realized = sum(r.realized_savings_usd for r in self._records)
        missed = max(0.0, total_projected - total_realized)
        realization_rate = (
            round((total_realized / total_projected) * 100, 2) if total_projected > 0 else 0.0
        )
        by_status: dict[str, float] = {}
        for r in self._records:
            key = r.savings_status.value
            by_status[key] = round(by_status.get(key, 0.0) + r.realized_savings_usd, 2)
        return {
            "total_projected_savings_usd": round(total_projected, 2),
            "total_realized_savings_usd": round(total_realized, 2),
            "missed_savings_usd": round(missed, 2),
            "realization_rate_pct": realization_rate,
            "savings_by_status": by_status,
            "record_count": len(self._records),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> TelemetryCostReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.cost_category.value] = by_e1.get(r.cost_category.value, 0) + 1
            by_e2[r.optimization_strategy.value] = by_e2.get(r.optimization_strategy.value, 0) + 1
            by_e3[r.savings_status.value] = by_e3.get(r.savings_status.value, 0) + 1
        total_cost = round(sum(r.cost_usd for r in self._records), 2)
        total_projected = round(sum(r.projected_savings_usd for r in self._records), 2)
        total_realized = round(sum(r.realized_savings_usd for r in self._records), 2)
        # Top cost pipelines
        by_pipeline: dict[str, float] = {}
        for r in self._records:
            by_pipeline[r.pipeline_name] = by_pipeline.get(r.pipeline_name, 0.0) + r.cost_usd
        sorted_pipelines = sorted(by_pipeline.items(), key=lambda x: x[1], reverse=True)
        top_pipelines = [p[0] for p in sorted_pipelines[:5]]
        recs: list[str] = []
        opportunities = self.identify_cost_reduction_opportunities()
        if opportunities:
            recs.append(f"{len(opportunities)} pipeline(s) have cost reduction opportunities")
        missed = max(0.0, total_projected - total_realized)
        if missed > 0:
            recs.append(f"${round(missed, 2)} in projected savings not yet realized")
        if not recs:
            recs.append("Telemetry cost optimization is on track")
        return TelemetryCostReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            total_cost_usd=total_cost,
            total_projected_savings_usd=total_projected,
            total_realized_savings_usd=total_realized,
            by_cost_category=by_e1,
            by_optimization_strategy=by_e2,
            by_savings_status=by_e3,
            top_cost_pipelines=top_pipelines,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("telemetry.cost.optimizer.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        category_dist: dict[str, int] = {}
        for r in self._records:
            key = r.cost_category.value
            category_dist[key] = category_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "cost_category_distribution": category_dist,
            "unique_pipelines": len({r.pipeline_name for r in self._records}),
            "unique_teams": len({r.team for r in self._records}),
        }
