"""Agent Self-Healing Engine — track and optimize agent automatic recovery."""

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
    FALLBACK = "fallback"
    CIRCUIT_BREAK = "circuit_break"
    DEGRADE_GRACEFULLY = "degrade_gracefully"


class FailureMode(StrEnum):
    TIMEOUT = "timeout"
    OOM = "oom"
    API_ERROR = "api_error"
    INVALID_STATE = "invalid_state"
    DEPENDENCY_FAILURE = "dependency_failure"


class RecoveryStatus(StrEnum):
    RECOVERED = "recovered"
    DEGRADED = "degraded"
    FAILED = "failed"
    MANUAL_INTERVENTION = "manual_intervention"


# --- Models ---


class HealingRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    healing_action: HealingAction = HealingAction.RESTART
    failure_mode: FailureMode = FailureMode.TIMEOUT
    recovery_status: RecoveryStatus = RecoveryStatus.RECOVERED
    score: float = 0.0
    recovery_time_ms: float = 0.0
    agent_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class HealingAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    healing_action: HealingAction = HealingAction.RESTART
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class HealingReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_action: dict[str, int] = Field(default_factory=dict)
    by_failure_mode: dict[str, int] = Field(default_factory=dict)
    by_recovery_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentSelfHealingEngine:
    """Track and optimize agent self-healing, circuit breaking, and degradation recovery."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[HealingRecord] = []
        self._analyses: list[HealingAnalysis] = []
        logger.info(
            "agent_self_healing_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        healing_action: HealingAction = HealingAction.RESTART,
        failure_mode: FailureMode = FailureMode.TIMEOUT,
        recovery_status: RecoveryStatus = RecoveryStatus.RECOVERED,
        score: float = 0.0,
        recovery_time_ms: float = 0.0,
        agent_id: str = "",
        service: str = "",
        team: str = "",
    ) -> HealingRecord:
        record = HealingRecord(
            name=name,
            healing_action=healing_action,
            failure_mode=failure_mode,
            recovery_status=recovery_status,
            score=score,
            recovery_time_ms=recovery_time_ms,
            agent_id=agent_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_self_healing_engine.record_added",
            record_id=record.id,
            name=name,
            healing_action=healing_action.value,
            failure_mode=failure_mode.value,
        )
        return record

    def get_record(self, record_id: str) -> HealingRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        healing_action: HealingAction | None = None,
        failure_mode: FailureMode | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[HealingRecord]:
        results = list(self._records)
        if healing_action is not None:
            results = [r for r in results if r.healing_action == healing_action]
        if failure_mode is not None:
            results = [r for r in results if r.failure_mode == failure_mode]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        healing_action: HealingAction = HealingAction.RESTART,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> HealingAnalysis:
        analysis = HealingAnalysis(
            name=name,
            healing_action=healing_action,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "agent_self_healing_engine.analysis_added",
            name=name,
            healing_action=healing_action.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def detect_degradation_patterns(self) -> list[dict[str, Any]]:
        """Find agents showing performance degradation trends over time."""
        agent_records: dict[str, list[HealingRecord]] = {}
        for r in self._records:
            agent_records.setdefault(r.agent_id, []).append(r)
        results: list[dict[str, Any]] = []
        for agent_id, records in agent_records.items():
            if len(records) < 2:
                continue
            mid = len(records) // 2
            first_scores = [r.score for r in records[:mid]]
            second_scores = [r.score for r in records[mid:]]
            avg_first = sum(first_scores) / len(first_scores)
            avg_second = sum(second_scores) / len(second_scores)
            delta = round(avg_second - avg_first, 2)
            if delta < -5.0:
                results.append(
                    {
                        "agent_id": agent_id,
                        "avg_first_half": round(avg_first, 2),
                        "avg_second_half": round(avg_second, 2),
                        "delta": delta,
                        "failure_count": len(records),
                        "trend": "degrading",
                    }
                )
        results.sort(key=lambda x: x["delta"])
        return results

    def recommend_healing_actions(self) -> list[dict[str, Any]]:
        """Suggest specific healing actions per failure mode based on success rates."""
        fm_action_outcomes: dict[str, dict[str, list[str]]] = {}
        for r in self._records:
            fm = r.failure_mode.value
            action = r.healing_action.value
            fm_action_outcomes.setdefault(fm, {}).setdefault(action, []).append(
                r.recovery_status.value
            )
        results: list[dict[str, Any]] = []
        for fm, actions in fm_action_outcomes.items():
            best_action = ""
            best_rate = -1.0
            for action, statuses in actions.items():
                recovered = sum(1 for s in statuses if s == "recovered")
                rate = recovered / len(statuses) * 100 if statuses else 0.0
                if rate > best_rate:
                    best_rate = rate
                    best_action = action
            results.append(
                {
                    "failure_mode": fm,
                    "recommended_action": best_action,
                    "recovery_rate": round(best_rate, 2),
                    "sample_size": sum(len(s) for s in actions.values()),
                }
            )
        results.sort(key=lambda x: x["recovery_rate"], reverse=True)
        return results

    def measure_self_healing_effectiveness(self) -> dict[str, Any]:
        """Track recovery success rate over time via split-half comparison."""
        if len(self._records) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        mid = len(self._records) // 2
        first_half = self._records[:mid]
        second_half = self._records[mid:]
        first_recovered = sum(
            1 for r in first_half if r.recovery_status == RecoveryStatus.RECOVERED
        )
        second_recovered = sum(
            1 for r in second_half if r.recovery_status == RecoveryStatus.RECOVERED
        )
        rate_first = round(first_recovered / len(first_half) * 100, 2)
        rate_second = round(second_recovered / len(second_half) * 100, 2)
        delta = round(rate_second - rate_first, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "rate_first_half": rate_first,
            "rate_second_half": rate_second,
            "total_records": len(self._records),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> HealingReport:
        by_action: dict[str, int] = {}
        by_failure_mode: dict[str, int] = {}
        by_recovery_status: dict[str, int] = {}
        for r in self._records:
            by_action[r.healing_action.value] = by_action.get(r.healing_action.value, 0) + 1
            by_failure_mode[r.failure_mode.value] = by_failure_mode.get(r.failure_mode.value, 0) + 1
            by_recovery_status[r.recovery_status.value] = (
                by_recovery_status.get(r.recovery_status.value, 0) + 1
            )
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = [r.name for r in self._records if r.score < self._threshold]
        top_gaps = gap_list[:5]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} healing event(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Agent Self-Healing Engine is healthy")
        return HealingReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_action=by_action,
            by_failure_mode=by_failure_mode,
            by_recovery_status=by_recovery_status,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_self_healing_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        action_dist: dict[str, int] = {}
        for r in self._records:
            key = r.healing_action.value
            action_dist[key] = action_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "action_distribution": action_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
