"""Error Budget Tracker Engine — track SLO error budget consumption."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BudgetState(StrEnum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    EXHAUSTED = "exhausted"
    EXCEEDED = "exceeded"


class BurnRateCategory(StrEnum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    HIGH = "high"
    EXTREME = "extreme"
    RECOVERED = "recovered"


class BudgetAction(StrEnum):
    NONE = "none"
    SLOW_DEPLOY = "slow_deploy"
    FREEZE_DEPLOY = "freeze_deploy"
    INCIDENT_RESPONSE = "incident_response"
    POSTMORTEM = "postmortem"


# --- Models ---


class ErrorBudgetTrackerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    slo_name: str = ""
    budget_state: BudgetState = BudgetState.HEALTHY
    burn_rate_category: BurnRateCategory = BurnRateCategory.NORMAL
    budget_action: BudgetAction = BudgetAction.NONE
    budget_total_minutes: float = 0.0
    budget_consumed_minutes: float = 0.0
    budget_remaining_pct: float = 100.0
    burn_rate_multiplier: float = 1.0
    window_days: int = 30
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ErrorBudgetTrackerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str = ""
    analysis_score: float = 0.0
    budget_state: BudgetState = BudgetState.HEALTHY
    projected_exhaustion_days: int = 0
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ErrorBudgetTrackerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_budget_remaining: float = 0.0
    by_state: dict[str, int] = Field(default_factory=dict)
    by_burn_rate: dict[str, int] = Field(default_factory=dict)
    by_action: dict[str, int] = Field(default_factory=dict)
    exhausted_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ErrorBudgetTrackerEngine:
    """Track SLO error budget consumption and burn rates."""

    def __init__(
        self,
        max_records: int = 200000,
        budget_threshold: float = 20.0,
    ) -> None:
        self._max_records = max_records
        self._budget_threshold = budget_threshold
        self._records: list[ErrorBudgetTrackerRecord] = []
        self._analyses: dict[str, ErrorBudgetTrackerAnalysis] = {}
        logger.info(
            "error_budget_tracker_engine.init",
            max_records=max_records,
            budget_threshold=budget_threshold,
        )

    def add_record(
        self,
        service_id: str = "",
        slo_name: str = "",
        budget_state: BudgetState = BudgetState.HEALTHY,
        burn_rate_category: BurnRateCategory = BurnRateCategory.NORMAL,
        budget_action: BudgetAction = BudgetAction.NONE,
        budget_total_minutes: float = 0.0,
        budget_consumed_minutes: float = 0.0,
        budget_remaining_pct: float = 100.0,
        burn_rate_multiplier: float = 1.0,
        window_days: int = 30,
        description: str = "",
    ) -> ErrorBudgetTrackerRecord:
        record = ErrorBudgetTrackerRecord(
            service_id=service_id,
            slo_name=slo_name,
            budget_state=budget_state,
            burn_rate_category=burn_rate_category,
            budget_action=budget_action,
            budget_total_minutes=budget_total_minutes,
            budget_consumed_minutes=budget_consumed_minutes,
            budget_remaining_pct=budget_remaining_pct,
            burn_rate_multiplier=burn_rate_multiplier,
            window_days=window_days,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "error_budget_tracker_engine.record_added",
            record_id=record.id,
            service_id=service_id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> ErrorBudgetTrackerAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        svc_recs = [r for r in self._records if r.service_id == rec.service_id]
        # Project exhaustion
        projected_days = 0
        if rec.burn_rate_multiplier > 0 and rec.budget_remaining_pct > 0:
            remaining_frac = rec.budget_remaining_pct / 100.0
            daily_burn = rec.burn_rate_multiplier / rec.window_days
            if daily_burn > 0:
                projected_days = int(remaining_frac / daily_burn)
        analysis = ErrorBudgetTrackerAnalysis(
            service_id=rec.service_id,
            analysis_score=rec.budget_remaining_pct,
            budget_state=rec.budget_state,
            projected_exhaustion_days=projected_days,
            data_points=len(svc_recs),
            description=(
                f"Error budget {rec.budget_remaining_pct}% remaining for {rec.service_id}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ErrorBudgetTrackerReport:
        by_s: dict[str, int] = {}
        by_br: dict[str, int] = {}
        by_a: dict[str, int] = {}
        remaining: list[float] = []
        for r in self._records:
            by_s[r.budget_state.value] = by_s.get(r.budget_state.value, 0) + 1
            by_br[r.burn_rate_category.value] = by_br.get(r.burn_rate_category.value, 0) + 1
            by_a[r.budget_action.value] = by_a.get(r.budget_action.value, 0) + 1
            remaining.append(r.budget_remaining_pct)
        avg_rem = round(sum(remaining) / len(remaining), 2) if remaining else 0.0
        exhausted = list(
            {
                r.service_id
                for r in self._records
                if r.budget_state in (BudgetState.EXHAUSTED, BudgetState.EXCEEDED)
            }
        )[:10]
        recs: list[str] = []
        if exhausted:
            recs.append(f"{len(exhausted)} services with exhausted error budget")
        critical = sum(1 for r in self._records if r.budget_remaining_pct < self._budget_threshold)
        if critical:
            recs.append(f"{critical} records below {self._budget_threshold}% budget remaining")
        if not recs:
            recs.append("Error budgets healthy across all services")
        return ErrorBudgetTrackerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_budget_remaining=avg_rem,
            by_state=by_s,
            by_burn_rate=by_br,
            by_action=by_a,
            exhausted_services=exhausted,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        state_dist: dict[str, int] = {}
        for r in self._records:
            k = r.budget_state.value
            state_dist[k] = state_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "budget_threshold": self._budget_threshold,
            "state_distribution": state_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("error_budget_tracker_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def rank_services_by_budget_risk(self) -> list[dict[str, Any]]:
        """Rank services by error budget risk (lowest remaining first)."""
        svc_budgets: dict[str, list[float]] = {}
        for r in self._records:
            svc_budgets.setdefault(r.service_id, []).append(r.budget_remaining_pct)
        results: list[dict[str, Any]] = []
        for sid, pcts in svc_budgets.items():
            latest = pcts[-1]
            avg = round(sum(pcts) / len(pcts), 2)
            results.append(
                {
                    "service_id": sid,
                    "latest_remaining_pct": latest,
                    "avg_remaining_pct": avg,
                    "data_points": len(pcts),
                }
            )
        results.sort(key=lambda x: x["latest_remaining_pct"])
        return results

    def compute_burn_rate_trends(self) -> list[dict[str, Any]]:
        """Compute burn rate trends per service."""
        svc_rates: dict[str, list[float]] = {}
        for r in self._records:
            svc_rates.setdefault(r.service_id, []).append(r.burn_rate_multiplier)
        results: list[dict[str, Any]] = []
        for sid, rates in svc_rates.items():
            if len(rates) < 2:
                continue
            mid = len(rates) // 2
            first = sum(rates[:mid]) / mid
            second = sum(rates[mid:]) / len(rates[mid:])
            delta = round(second - first, 2)
            trend = "stable" if abs(delta) < 0.5 else ("increasing" if delta > 0 else "decreasing")
            results.append(
                {
                    "service_id": sid,
                    "burn_rate_trend": trend,
                    "delta": delta,
                    "latest_rate": rates[-1],
                }
            )
        results.sort(key=lambda x: x["delta"], reverse=True)
        return results

    def recommend_budget_actions(self) -> list[dict[str, Any]]:
        """Recommend actions based on current budget state."""
        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        for r in sorted(self._records, key=lambda x: x.budget_remaining_pct):
            if r.service_id in seen:
                continue
            seen.add(r.service_id)
            if r.budget_remaining_pct <= 0:
                action = "freeze_deploy"
            elif r.budget_remaining_pct < 10:
                action = "incident_response"
            elif r.budget_remaining_pct < self._budget_threshold:
                action = "slow_deploy"
            else:
                action = "none"
            if action != "none":
                results.append(
                    {
                        "service_id": r.service_id,
                        "slo_name": r.slo_name,
                        "budget_remaining_pct": r.budget_remaining_pct,
                        "recommended_action": action,
                    }
                )
        return results
