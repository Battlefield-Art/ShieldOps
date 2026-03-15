"""OTelTraceSamplingOptimizerEngine — optimize trace sampling rates to balance
cost vs. fidelity."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SamplingStrategy(StrEnum):
    FULL_FIDELITY = "full_fidelity"
    HEAD_BASED = "head_based"
    TAIL_BASED = "tail_based"
    ADAPTIVE = "adaptive"
    PRIORITY_BASED = "priority_based"


class TraceImportance(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"
    NOISE = "noise"


class SamplingOptimization(StrEnum):
    COST_OPTIMIZED = "cost_optimized"
    FIDELITY_OPTIMIZED = "fidelity_optimized"
    BALANCED = "balanced"
    INCIDENT_FOCUSED = "incident_focused"


# --- Models ---


class TraceSamplingRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str = ""
    sampling_strategy: SamplingStrategy = SamplingStrategy.HEAD_BASED
    trace_importance: TraceImportance = TraceImportance.NORMAL
    sampling_optimization: SamplingOptimization = SamplingOptimization.BALANCED
    current_rate: float = 1.0
    traces_per_second: float = 0.0
    cost_per_day_usd: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class TraceSamplingAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str = ""
    avg_rate: float = 0.0
    avg_cost: float = 0.0
    recommended_rate: float = 1.0
    projected_savings_usd: float = 0.0
    sampling_strategy: SamplingStrategy = SamplingStrategy.HEAD_BASED
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TraceSamplingReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_sampling_rate: float = 0.0
    total_cost_per_day_usd: float = 0.0
    by_sampling_strategy: dict[str, int] = Field(default_factory=dict)
    by_trace_importance: dict[str, int] = Field(default_factory=dict)
    by_sampling_optimization: dict[str, int] = Field(default_factory=dict)
    over_sampled_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OTelTraceSamplingOptimizerEngine:
    """Optimize trace sampling rates to balance cost vs. fidelity."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 0.5,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[TraceSamplingRecord] = []
        self._analyses: list[TraceSamplingAnalysis] = []
        logger.info(
            "otel.trace.sampling.optimizer.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        service_name: str,
        sampling_strategy: SamplingStrategy = SamplingStrategy.HEAD_BASED,
        trace_importance: TraceImportance = TraceImportance.NORMAL,
        sampling_optimization: SamplingOptimization = SamplingOptimization.BALANCED,
        current_rate: float = 1.0,
        traces_per_second: float = 0.0,
        cost_per_day_usd: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> TraceSamplingRecord:
        record = TraceSamplingRecord(
            service_name=service_name,
            sampling_strategy=sampling_strategy,
            trace_importance=trace_importance,
            sampling_optimization=sampling_optimization,
            current_rate=current_rate,
            traces_per_second=traces_per_second,
            cost_per_day_usd=cost_per_day_usd,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel.trace.sampling.optimizer.record_added",
            record_id=record.id,
            service_name=service_name,
            sampling_strategy=sampling_strategy.value,
        )
        return record

    def get_record(self, record_id: str) -> TraceSamplingRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        service_name: str | None = None,
        sampling_strategy: SamplingStrategy | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[TraceSamplingRecord]:
        results = list(self._records)
        if service_name is not None:
            results = [r for r in results if r.service_name == service_name]
        if sampling_strategy is not None:
            results = [r for r in results if r.sampling_strategy == sampling_strategy]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, service_name: str) -> TraceSamplingAnalysis | None:
        records = [r for r in self._records if r.service_name == service_name]
        if not records:
            return None
        rates = [r.current_rate for r in records]
        costs = [r.cost_per_day_usd for r in records]
        avg_rate = round(sum(rates) / len(rates), 4)
        avg_cost = round(sum(costs) / len(costs), 2)
        # Recommend lower rate for low-importance, high-volume services
        importances = [r.trace_importance for r in records]
        has_low = any(i in (TraceImportance.LOW, TraceImportance.NOISE) for i in importances)
        has_critical = any(i == TraceImportance.CRITICAL for i in importances)
        if has_critical:
            recommended_rate = min(1.0, avg_rate * 1.2)
        elif has_low and avg_rate > self._threshold:
            recommended_rate = max(0.01, avg_rate * 0.5)
        elif avg_rate > self._threshold:
            recommended_rate = max(0.01, avg_rate * 0.7)
        else:
            recommended_rate = avg_rate
        projected_savings = round(
            avg_cost * (1.0 - recommended_rate / avg_rate) if avg_rate > 0 else 0.0, 2
        )
        analysis = TraceSamplingAnalysis(
            service_name=service_name,
            avg_rate=round(avg_rate, 4),
            avg_cost=avg_cost,
            recommended_rate=round(recommended_rate, 4),
            projected_savings_usd=max(0.0, projected_savings),
            sampling_strategy=records[-1].sampling_strategy,
            description=(
                f"Sampling optimization for {service_name}: "
                f"rate {avg_rate:.4f} -> {recommended_rate:.4f}"
            ),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel.trace.sampling.optimizer.processed",
            service_name=service_name,
            avg_rate=avg_rate,
            recommended_rate=recommended_rate,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def recommend_sampling_rate(self, service_name: str) -> dict[str, Any]:
        """Recommend per-service sampling rate."""
        records = [r for r in self._records if r.service_name == service_name]
        if not records:
            return {"service_name": service_name, "status": "no_data"}
        rates = [r.current_rate for r in records]
        avg_rate = sum(rates) / len(rates)
        avg_tps = sum(r.traces_per_second for r in records) / len(records)
        importances = [r.trace_importance for r in records]
        has_critical = any(i == TraceImportance.CRITICAL for i in importances)
        has_noise = any(i == TraceImportance.NOISE for i in importances)
        if has_critical:
            recommended = min(1.0, max(avg_rate, 0.9))
        elif has_noise:
            recommended = max(0.01, avg_rate * 0.3)
        elif avg_tps > 1000:
            recommended = max(0.01, min(avg_rate, 0.1))
        elif avg_rate > self._threshold:
            recommended = max(0.01, avg_rate * 0.6)
        else:
            recommended = avg_rate
        return {
            "service_name": service_name,
            "current_avg_rate": round(avg_rate, 4),
            "recommended_rate": round(recommended, 4),
            "avg_traces_per_second": round(avg_tps, 2),
            "record_count": len(records),
            "has_critical_traces": has_critical,
        }

    def estimate_cost_savings(self, target_rate: float) -> dict[str, Any]:
        """Estimate cost reduction from lower sampling."""
        if not self._records:
            return {"status": "no_data", "projected_savings_usd": 0.0}
        total_current_cost = sum(r.cost_per_day_usd for r in self._records)
        avg_current_rate = sum(r.current_rate for r in self._records) / len(self._records)
        if avg_current_rate > 0:
            reduction_factor = 1.0 - (target_rate / avg_current_rate)
        else:
            reduction_factor = 0.0
        projected_savings = round(max(0.0, total_current_cost * reduction_factor), 2)
        return {
            "current_total_cost_per_day_usd": round(total_current_cost, 2),
            "avg_current_rate": round(avg_current_rate, 4),
            "target_rate": target_rate,
            "projected_daily_savings_usd": projected_savings,
            "projected_monthly_savings_usd": round(projected_savings * 30, 2),
            "reduction_factor": round(reduction_factor, 4),
        }

    def identify_over_sampled_services(self) -> list[dict[str, Any]]:
        """Find services generating excess trace data."""
        by_service: dict[str, list[TraceSamplingRecord]] = {}
        for r in self._records:
            by_service.setdefault(r.service_name, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, recs in by_service.items():
            avg_rate = sum(r.current_rate for r in recs) / len(recs)
            avg_tps = sum(r.traces_per_second for r in recs) / len(recs)
            total_cost = sum(r.cost_per_day_usd for r in recs)
            importances = [r.trace_importance for r in recs]
            is_low_importance = all(
                i in (TraceImportance.LOW, TraceImportance.NOISE, TraceImportance.NORMAL)
                for i in importances
            )
            if avg_rate > self._threshold and is_low_importance:
                results.append(
                    {
                        "service_name": svc,
                        "avg_rate": round(avg_rate, 4),
                        "avg_traces_per_second": round(avg_tps, 2),
                        "total_cost_per_day_usd": round(total_cost, 2),
                        "record_count": len(recs),
                    }
                )
        results.sort(key=lambda x: x["total_cost_per_day_usd"], reverse=True)
        return results

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> TraceSamplingReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.sampling_strategy.value] = by_e1.get(r.sampling_strategy.value, 0) + 1
            by_e2[r.trace_importance.value] = by_e2.get(r.trace_importance.value, 0) + 1
            by_e3[r.sampling_optimization.value] = by_e3.get(r.sampling_optimization.value, 0) + 1
        rates = [r.current_rate for r in self._records]
        avg_rate = round(sum(rates) / len(rates), 4) if rates else 0.0
        total_cost = round(sum(r.cost_per_day_usd for r in self._records), 2)
        over_sampled = self.identify_over_sampled_services()
        over_sampled_names = [o["service_name"] for o in over_sampled[:5]]
        recs: list[str] = []
        if over_sampled:
            recs.append(
                f"{len(over_sampled)} service(s) over-sampled above threshold ({self._threshold})"
            )
        if avg_rate > self._threshold and self._records:
            recs.append(f"Avg sampling rate {avg_rate} exceeds threshold ({self._threshold})")
        if not recs:
            recs.append("Trace sampling rates are well-optimized")
        return TraceSamplingReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_sampling_rate=avg_rate,
            total_cost_per_day_usd=total_cost,
            by_sampling_strategy=by_e1,
            by_trace_importance=by_e2,
            by_sampling_optimization=by_e3,
            over_sampled_services=over_sampled_names,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel.trace.sampling.optimizer.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        strategy_dist: dict[str, int] = {}
        for r in self._records:
            key = r.sampling_strategy.value
            strategy_dist[key] = strategy_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "sampling_strategy_distribution": strategy_dist,
            "unique_services": len({r.service_name for r in self._records}),
            "unique_teams": len({r.team for r in self._records}),
        }
