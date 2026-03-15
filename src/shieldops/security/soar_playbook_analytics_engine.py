"""SOAR Playbook Analytics Engine —
analyze SOAR playbook performance, identify automation candidates,
and calculate mean time to respond across security operations."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PlaybookOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    TIMEOUT = "timeout"


class AutomationLevel(StrEnum):
    FULL = "full"
    SEMI = "semi"
    MANUAL = "manual"


class PlaybookTier(StrEnum):
    CRITICAL = "critical"
    STANDARD = "standard"
    LOW = "low"


# --- Models ---


class SoarPlaybookAnalyticsRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    playbook_name: str = ""
    incident_type: str = ""
    playbook_outcome: PlaybookOutcome = PlaybookOutcome.FAILURE
    automation_level: AutomationLevel = AutomationLevel.MANUAL
    playbook_tier: PlaybookTier = PlaybookTier.STANDARD
    execution_time_seconds: float = 0.0
    response_time_seconds: float = 0.0
    step_count: int = 0
    automated_steps: int = 0
    manual_steps: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SoarPlaybookAnalyticsAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    playbook_name: str = ""
    performance_score: float = 0.0
    automation_potential: float = 0.0
    playbook_outcome: PlaybookOutcome = PlaybookOutcome.FAILURE
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SoarPlaybookAnalyticsReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_execution_time: float = 0.0
    by_playbook_outcome: dict[str, int] = Field(default_factory=dict)
    by_automation_level: dict[str, int] = Field(default_factory=dict)
    by_playbook_tier: dict[str, int] = Field(default_factory=dict)
    underperforming_playbooks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class SoarPlaybookAnalyticsEngine:
    """Analyze SOAR playbook performance, identify automation candidates,
    and calculate mean time to respond across security operations."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[SoarPlaybookAnalyticsRecord] = []
        self._analyses: dict[str, SoarPlaybookAnalyticsAnalysis] = {}
        logger.info(
            "soar_playbook_analytics_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        playbook_name: str = "",
        incident_type: str = "",
        playbook_outcome: PlaybookOutcome = PlaybookOutcome.FAILURE,
        automation_level: AutomationLevel = AutomationLevel.MANUAL,
        playbook_tier: PlaybookTier = PlaybookTier.STANDARD,
        execution_time_seconds: float = 0.0,
        response_time_seconds: float = 0.0,
        step_count: int = 0,
        automated_steps: int = 0,
        manual_steps: int = 0,
        description: str = "",
    ) -> SoarPlaybookAnalyticsRecord:
        record = SoarPlaybookAnalyticsRecord(
            playbook_name=playbook_name,
            incident_type=incident_type,
            playbook_outcome=playbook_outcome,
            automation_level=automation_level,
            playbook_tier=playbook_tier,
            execution_time_seconds=execution_time_seconds,
            response_time_seconds=response_time_seconds,
            step_count=step_count,
            automated_steps=automated_steps,
            manual_steps=manual_steps,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "soar_playbook_analytics.record_added",
            record_id=record.id,
            playbook_name=playbook_name,
        )
        return record

    def process(self, key: str) -> SoarPlaybookAnalyticsAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        outcome_score = {
            PlaybookOutcome.SUCCESS: 1.0,
            PlaybookOutcome.PARTIAL: 0.6,
            PlaybookOutcome.FAILURE: 0.2,
            PlaybookOutcome.TIMEOUT: 0.1,
        }
        perf_score = round(outcome_score.get(rec.playbook_outcome, 0.0), 4)
        auto_potential = round(rec.manual_steps / rec.step_count, 4) if rec.step_count > 0 else 0.0
        analysis = SoarPlaybookAnalyticsAnalysis(
            playbook_name=rec.playbook_name,
            performance_score=perf_score,
            automation_potential=auto_potential,
            playbook_outcome=rec.playbook_outcome,
            description=(
                f"Playbook {rec.playbook_name} -> performance={perf_score} "
                f"automation_potential={auto_potential}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> SoarPlaybookAnalyticsReport:
        by_outcome: dict[str, int] = {}
        by_auto: dict[str, int] = {}
        by_tier: dict[str, int] = {}
        exec_times: list[float] = []
        for r in self._records:
            by_outcome[r.playbook_outcome.value] = by_outcome.get(r.playbook_outcome.value, 0) + 1
            by_auto[r.automation_level.value] = by_auto.get(r.automation_level.value, 0) + 1
            by_tier[r.playbook_tier.value] = by_tier.get(r.playbook_tier.value, 0) + 1
            exec_times.append(r.execution_time_seconds)
        avg_exec = round(sum(exec_times) / len(exec_times), 4) if exec_times else 0.0
        underperforming = list(
            {
                r.playbook_name
                for r in self._records
                if r.playbook_outcome in (PlaybookOutcome.FAILURE, PlaybookOutcome.TIMEOUT)
                and r.playbook_name
            }
        )[:10]
        recs: list[str] = []
        if underperforming:
            recs.append(f"{len(underperforming)} playbooks have failure/timeout outcomes")
        if avg_exec > 3600:
            recs.append("Average execution time exceeds 1 hour")
        if not recs:
            recs.append("SOAR playbook analytics operating within normal parameters")
        return SoarPlaybookAnalyticsReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_execution_time=avg_exec,
            by_playbook_outcome=by_outcome,
            by_automation_level=by_auto,
            by_playbook_tier=by_tier,
            underperforming_playbooks=underperforming,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        outcome_dist: dict[str, int] = {}
        for r in self._records:
            outcome_dist[r.playbook_outcome.value] = (
                outcome_dist.get(r.playbook_outcome.value, 0) + 1
            )
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "playbook_outcome_distribution": outcome_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("soar_playbook_analytics_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def rank_playbooks_by_performance(self) -> list[dict[str, Any]]:
        """Rank playbooks by historical performance metrics."""
        playbook_data: dict[str, list[SoarPlaybookAnalyticsRecord]] = {}
        for r in self._records:
            if r.playbook_name:
                playbook_data.setdefault(r.playbook_name, []).append(r)
        results: list[dict[str, Any]] = []
        for name, recs in playbook_data.items():
            success_count = sum(1 for r in recs if r.playbook_outcome == PlaybookOutcome.SUCCESS)
            success_rate = round(success_count / len(recs), 4)
            avg_exec = round(sum(r.execution_time_seconds for r in recs) / len(recs), 4)
            tiers = list({r.playbook_tier.value for r in recs})
            results.append(
                {
                    "playbook_name": name,
                    "success_rate": success_rate,
                    "avg_execution_time": avg_exec,
                    "execution_count": len(recs),
                    "tiers": tiers,
                    "rank_tier": (
                        "top" if success_rate >= 0.8 else "mid" if success_rate >= 0.5 else "low"
                    ),
                }
            )
        results.sort(key=lambda x: x["success_rate"], reverse=True)
        return results

    def identify_automation_candidates(self) -> list[dict[str, Any]]:
        """Identify playbooks with high automation potential."""
        playbook_data: dict[str, list[SoarPlaybookAnalyticsRecord]] = {}
        for r in self._records:
            if r.playbook_name:
                playbook_data.setdefault(r.playbook_name, []).append(r)
        results: list[dict[str, Any]] = []
        for name, recs in playbook_data.items():
            manual_recs = [r for r in recs if r.automation_level == AutomationLevel.MANUAL]
            if not manual_recs:
                continue
            avg_manual_steps = round(sum(r.manual_steps for r in manual_recs) / len(manual_recs), 4)
            avg_total_steps = round(sum(r.step_count for r in manual_recs) / len(manual_recs), 4)
            automation_potential = (
                round(avg_manual_steps / avg_total_steps, 4) if avg_total_steps > 0 else 0.0
            )
            results.append(
                {
                    "playbook_name": name,
                    "automation_potential": automation_potential,
                    "avg_manual_steps": avg_manual_steps,
                    "avg_total_steps": avg_total_steps,
                    "manual_execution_count": len(manual_recs),
                    "priority": (
                        "high"
                        if automation_potential >= 0.7
                        else "medium"
                        if automation_potential >= 0.4
                        else "low"
                    ),
                }
            )
        results.sort(key=lambda x: x["automation_potential"], reverse=True)
        return results

    def calculate_mean_time_to_respond(self) -> list[dict[str, Any]]:
        """Calculate MTTR per incident type and playbook."""
        incident_data: dict[str, list[SoarPlaybookAnalyticsRecord]] = {}
        for r in self._records:
            if r.incident_type:
                incident_data.setdefault(r.incident_type, []).append(r)
        results: list[dict[str, Any]] = []
        for inc_type, recs in incident_data.items():
            avg_response = round(sum(r.response_time_seconds for r in recs) / len(recs), 4)
            avg_execution = round(sum(r.execution_time_seconds for r in recs) / len(recs), 4)
            mttr = round(avg_response + avg_execution, 4)
            playbooks = list({r.playbook_name for r in recs if r.playbook_name})
            results.append(
                {
                    "incident_type": inc_type,
                    "mean_time_to_respond": mttr,
                    "avg_response_time": avg_response,
                    "avg_execution_time": avg_execution,
                    "playbook_count": len(playbooks),
                    "incident_count": len(recs),
                    "rating": (
                        "excellent" if mttr < 300 else "good" if mttr < 900 else "needs_improvement"
                    ),
                }
            )
        results.sort(key=lambda x: x["mean_time_to_respond"])
        return results
