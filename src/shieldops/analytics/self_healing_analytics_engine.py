"""Self-Healing Analytics Engine —
analyze self-healing automation effectiveness, identify healing patterns,
and recommend improvements to autonomous remediation workflows."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class HealingAction(StrEnum):
    RESTART = "restart"
    SCALE = "scale"
    FAILOVER = "failover"
    ROLLBACK = "rollback"


class HealingOutcome(StrEnum):
    RESOLVED = "resolved"
    PARTIAL = "partial"
    FAILED = "failed"
    ESCALATED = "escalated"


class HealingTrigger(StrEnum):
    ALERT = "alert"
    THRESHOLD = "threshold"
    PREDICTION = "prediction"
    MANUAL = "manual"


# --- Models ---


class SelfHealingRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str = ""
    incident_id: str = ""
    healing_action: HealingAction = HealingAction.RESTART
    healing_outcome: HealingOutcome = HealingOutcome.FAILED
    healing_trigger: HealingTrigger = HealingTrigger.ALERT
    execution_time_seconds: float = 0.0
    downtime_seconds: float = 0.0
    success_rate: float = 0.0
    retry_count: int = 0
    confidence_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SelfHealingAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str = ""
    healing_action: HealingAction = HealingAction.RESTART
    healing_outcome: HealingOutcome = HealingOutcome.FAILED
    effectiveness_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SelfHealingReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_success_rate: float = 0.0
    by_healing_action: dict[str, int] = Field(default_factory=dict)
    by_healing_outcome: dict[str, int] = Field(default_factory=dict)
    by_healing_trigger: dict[str, int] = Field(default_factory=dict)
    failing_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class SelfHealingAnalyticsEngine:
    """Analyze self-healing automation effectiveness, identify healing patterns,
    and recommend improvements to autonomous remediation workflows."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[SelfHealingRecord] = []
        self._analyses: dict[str, SelfHealingAnalysis] = {}
        logger.info(
            "self_healing_analytics_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        service_name: str = "",
        incident_id: str = "",
        healing_action: HealingAction = HealingAction.RESTART,
        healing_outcome: HealingOutcome = HealingOutcome.FAILED,
        healing_trigger: HealingTrigger = HealingTrigger.ALERT,
        execution_time_seconds: float = 0.0,
        downtime_seconds: float = 0.0,
        success_rate: float = 0.0,
        retry_count: int = 0,
        confidence_score: float = 0.0,
        description: str = "",
    ) -> SelfHealingRecord:
        record = SelfHealingRecord(
            service_name=service_name,
            incident_id=incident_id,
            healing_action=healing_action,
            healing_outcome=healing_outcome,
            healing_trigger=healing_trigger,
            execution_time_seconds=execution_time_seconds,
            downtime_seconds=downtime_seconds,
            success_rate=success_rate,
            retry_count=retry_count,
            confidence_score=confidence_score,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "self_healing_analytics.record_added",
            record_id=record.id,
            service_name=service_name,
        )
        return record

    def process(self, key: str) -> SelfHealingAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        if rec.healing_outcome == HealingOutcome.RESOLVED:
            effectiveness = round(rec.success_rate * rec.confidence_score, 4)
        elif rec.healing_outcome == HealingOutcome.PARTIAL:
            effectiveness = round(rec.success_rate * 0.5, 4)
        elif rec.healing_outcome == HealingOutcome.ESCALATED:
            effectiveness = round(rec.success_rate * 0.3, 4)
        else:
            effectiveness = 0.0
        analysis = SelfHealingAnalysis(
            service_name=rec.service_name,
            healing_action=rec.healing_action,
            healing_outcome=rec.healing_outcome,
            effectiveness_score=effectiveness,
            description=(
                f"Service {rec.service_name} -> {rec.healing_action.value} "
                f"outcome={rec.healing_outcome.value} effectiveness={effectiveness}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> SelfHealingReport:
        by_action: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        by_trigger: dict[str, int] = {}
        rates: list[float] = []
        for r in self._records:
            by_action[r.healing_action.value] = by_action.get(r.healing_action.value, 0) + 1
            by_outcome[r.healing_outcome.value] = by_outcome.get(r.healing_outcome.value, 0) + 1
            by_trigger[r.healing_trigger.value] = by_trigger.get(r.healing_trigger.value, 0) + 1
            rates.append(r.success_rate)
        avg_rate = round(sum(rates) / len(rates), 4) if rates else 0.0
        failing = list(
            {
                r.service_name
                for r in self._records
                if r.healing_outcome in (HealingOutcome.FAILED, HealingOutcome.ESCALATED)
                and r.service_name
            }
        )[:10]
        recs: list[str] = []
        if failing:
            recs.append(f"{len(failing)} services have failed/escalated healing actions")
        if avg_rate < 0.5:
            recs.append("Average healing success rate is below 50%")
        if not recs:
            recs.append("Self-healing analytics operating within normal parameters")
        return SelfHealingReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_success_rate=avg_rate,
            by_healing_action=by_action,
            by_healing_outcome=by_outcome,
            by_healing_trigger=by_trigger,
            failing_services=failing,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        action_dist: dict[str, int] = {}
        for r in self._records:
            action_dist[r.healing_action.value] = action_dist.get(r.healing_action.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "healing_action_distribution": action_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("self_healing_analytics_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def evaluate_healing_effectiveness(self) -> list[dict[str, Any]]:
        """Evaluate healing effectiveness per action type."""
        action_data: dict[str, list[SelfHealingRecord]] = {}
        for r in self._records:
            action_data.setdefault(r.healing_action.value, []).append(r)
        results: list[dict[str, Any]] = []
        for action, recs in action_data.items():
            resolved = sum(1 for r in recs if r.healing_outcome == HealingOutcome.RESOLVED)
            success_rate = round(resolved / len(recs), 4)
            avg_exec_time = round(sum(r.execution_time_seconds for r in recs) / len(recs), 4)
            avg_downtime = round(sum(r.downtime_seconds for r in recs) / len(recs), 4)
            results.append(
                {
                    "healing_action": action,
                    "success_rate": success_rate,
                    "avg_execution_time": avg_exec_time,
                    "avg_downtime": avg_downtime,
                    "total_executions": len(recs),
                    "rating": (
                        "excellent"
                        if success_rate >= 0.9
                        else "good"
                        if success_rate >= 0.7
                        else "needs_improvement"
                        if success_rate >= 0.5
                        else "poor"
                    ),
                }
            )
        results.sort(key=lambda x: x["success_rate"], reverse=True)
        return results

    def identify_healing_patterns(self) -> list[dict[str, Any]]:
        """Identify patterns in healing triggers and outcomes."""
        trigger_action: dict[str, dict[str, int]] = {}
        for r in self._records:
            trigger = r.healing_trigger.value
            action = r.healing_action.value
            trigger_action.setdefault(trigger, {})
            trigger_action[trigger][action] = trigger_action[trigger].get(action, 0) + 1
        results: list[dict[str, Any]] = []
        for trigger, actions in trigger_action.items():
            total = sum(actions.values())
            dominant_action = max(actions, key=actions.get)  # type: ignore[arg-type]
            trigger_recs = [r for r in self._records if r.healing_trigger.value == trigger]
            resolved = sum(1 for r in trigger_recs if r.healing_outcome == HealingOutcome.RESOLVED)
            results.append(
                {
                    "trigger": trigger,
                    "dominant_action": dominant_action,
                    "action_distribution": actions,
                    "total_events": total,
                    "resolution_rate": round(resolved / total, 4) if total else 0.0,
                    "pattern_strength": (
                        "strong"
                        if actions[dominant_action] / total >= 0.7
                        else "moderate"
                        if actions[dominant_action] / total >= 0.4
                        else "weak"
                    ),
                }
            )
        results.sort(key=lambda x: x["total_events"], reverse=True)
        return results

    def recommend_healing_improvements(self) -> list[dict[str, Any]]:
        """Recommend improvements to healing workflows per service."""
        service_data: dict[str, list[SelfHealingRecord]] = {}
        for r in self._records:
            if r.service_name:
                service_data.setdefault(r.service_name, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, recs in service_data.items():
            failed = sum(
                1
                for r in recs
                if r.healing_outcome in (HealingOutcome.FAILED, HealingOutcome.ESCALATED)
            )
            failure_rate = round(failed / len(recs), 4) if recs else 0.0
            avg_retries = round(sum(r.retry_count for r in recs) / len(recs), 4)
            avg_confidence = round(sum(r.confidence_score for r in recs) / len(recs), 4)
            improvements: list[str] = []
            if failure_rate > 0.3:
                improvements.append("Review healing action selection logic")
            if avg_retries > 2:
                improvements.append("Reduce retry count — consider alternative actions")
            if avg_confidence < 0.5:
                improvements.append("Improve confidence scoring model")
            if not improvements:
                improvements.append("Healing workflow performing well")
            results.append(
                {
                    "service_name": svc,
                    "failure_rate": failure_rate,
                    "avg_retry_count": avg_retries,
                    "avg_confidence": avg_confidence,
                    "record_count": len(recs),
                    "improvements": improvements,
                }
            )
        results.sort(key=lambda x: x["failure_rate"], reverse=True)
        return results
