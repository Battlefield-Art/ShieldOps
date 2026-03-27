"""DLP Policy Optimizer — optimize and tune DLP."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PolicyScope(StrEnum):
    ENDPOINT = "endpoint"
    NETWORK = "network"
    CLOUD = "cloud"
    EMAIL = "email"
    ALL = "all"


class OptimizationTarget(StrEnum):
    REDUCE_FP = "reduce_false_positives"
    INCREASE_DETECTION = "increase_detection"
    BALANCE = "balance"
    PERFORMANCE = "performance"
    COMPLIANCE = "compliance"


class FalsePositiveRate(StrEnum):
    NEGLIGIBLE = "negligible"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    EXCESSIVE = "excessive"


# --- Models ---


class DLPPolicyRecord(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    policy_id: str = ""
    scope: PolicyScope = PolicyScope.ENDPOINT
    target: OptimizationTarget = OptimizationTarget.BALANCE
    fp_rate: FalsePositiveRate = FalsePositiveRate.LOW
    true_positives: int = 0
    false_positives: int = 0
    total_events: int = 0
    created_at: float = Field(default_factory=time.time)


class DLPPolicyAnalysis(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    policy_id: str = ""
    fp_rate_pct: float = 0.0
    precision_pct: float = 0.0
    events_evaluated: int = 0
    analyzed_at: float = Field(default_factory=time.time)


class DLPPolicyReport(BaseModel):
    total_policies: int = 0
    avg_fp_rate_pct: float = 0.0
    high_fp_policies: int = 0
    by_scope: dict[str, int] = Field(
        default_factory=dict,
    )
    by_fp_rate: dict[str, int] = Field(
        default_factory=dict,
    )
    recommendations: list[str] = Field(
        default_factory=list,
    )
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class DLPPolicyOptimizer:
    """Optimize DLP policies to reduce FP."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[DLPPolicyRecord] = []
        logger.info(
            "dlp_policy_optimizer.initialized",
            max_records=max_records,
        )

    def _evict(self) -> None:
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]

    def record_item(
        self,
        **kwargs: Any,
    ) -> DLPPolicyRecord:
        record = DLPPolicyRecord(**kwargs)
        self._records.append(record)
        self._evict()
        logger.info(
            "dlp_policy.item_recorded",
            record_id=record.id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> DLPPolicyAnalysis:
        matches = [r for r in self._records if r.policy_id == key]
        if not matches:
            return DLPPolicyAnalysis(policy_id=key)
        total_fp = sum(r.false_positives for r in matches)
        total_tp = sum(r.true_positives for r in matches)
        total_ev = sum(r.total_events for r in matches)
        fp_rate = (
            round(
                total_fp / total_ev * 100,
                2,
            )
            if total_ev
            else 0.0
        )
        precision = (
            round(
                total_tp / (total_tp + total_fp) * 100,
                2,
            )
            if (total_tp + total_fp)
            else 0.0
        )
        return DLPPolicyAnalysis(
            policy_id=key,
            fp_rate_pct=fp_rate,
            precision_pct=precision,
            events_evaluated=total_ev,
        )

    def generate_report(self) -> DLPPolicyReport:
        by_scope: dict[str, int] = {}
        by_fp: dict[str, int] = {}
        policies: set[str] = set()
        high_fp = 0
        fp_rates: list[float] = []
        for r in self._records:
            s = r.scope.value
            by_scope[s] = by_scope.get(s, 0) + 1
            f = r.fp_rate.value
            by_fp[f] = by_fp.get(f, 0) + 1
            policies.add(r.policy_id)
            if r.fp_rate in (
                FalsePositiveRate.HIGH,
                FalsePositiveRate.EXCESSIVE,
            ):
                high_fp += 1
            if r.total_events > 0:
                fp_rates.append(
                    r.false_positives / r.total_events * 100,
                )
        avg_fp = (
            round(
                sum(fp_rates) / len(fp_rates),
                2,
            )
            if fp_rates
            else 0.0
        )
        recs: list[str] = []
        if high_fp > 0:
            recs.append(f"{high_fp} high-FP policy(ies)")
        if avg_fp > 20:
            recs.append("Avg FP rate exceeds 20%")
        if not recs:
            recs.append("DLP policies optimized")
        return DLPPolicyReport(
            total_policies=len(policies),
            avg_fp_rate_pct=avg_fp,
            high_fp_policies=high_fp,
            by_scope=by_scope,
            by_fp_rate=by_fp,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("dlp_policy_optimizer.cleared")
        return {"status": "cleared"}

    # -- domain methods --

    def optimize_policy(
        self,
        policy_id: str,
        target: OptimizationTarget = (OptimizationTarget.BALANCE),
    ) -> dict[str, Any]:
        """Optimize a DLP policy."""
        analysis = self.process(policy_id)
        return {
            "policy_id": policy_id,
            "target": target.value,
            "current_fp_rate": analysis.fp_rate_pct,
            "precision": analysis.precision_pct,
            "optimized": True,
        }

    def reduce_false_positives(
        self,
        policy_id: str,
    ) -> dict[str, Any]:
        """Reduce FP for a specific policy."""
        matches = [r for r in self._records if r.policy_id == policy_id]
        total_fp = sum(r.false_positives for r in matches)
        return {
            "policy_id": policy_id,
            "current_fp": total_fp,
            "recommendation": ("tighten_patterns" if total_fp > 10 else "no_change"),
        }

    def balance_security_usability(
        self,
    ) -> dict[str, Any]:
        """Balance security vs usability."""
        policies: dict[str, dict[str, int]] = {}
        for r in self._records:
            pid = r.policy_id
            if pid not in policies:
                policies[pid] = {"fp": 0, "tp": 0}
            policies[pid]["fp"] += r.false_positives
            policies[pid]["tp"] += r.true_positives
        balanced: list[str] = []
        needs_tuning: list[str] = []
        for pid, counts in policies.items():
            total = counts["fp"] + counts["tp"]
            if total == 0:
                continue
            fp_ratio = counts["fp"] / total
            if fp_ratio > 0.3:
                needs_tuning.append(pid)
            else:
                balanced.append(pid)
        return {
            "balanced_policies": len(balanced),
            "needs_tuning": len(needs_tuning),
            "tune_list": needs_tuning[:10],
        }
