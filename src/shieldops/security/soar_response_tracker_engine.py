"""SoarResponseTrackerEngine — Track SOAR response workflow execution metrics."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ResponsePhase(StrEnum):
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"


class AutomationLevel(StrEnum):
    FULL_AUTO = "full_auto"
    SEMI_AUTO = "semi_auto"
    MANUAL = "manual"


class ResponseEffectiveness(StrEnum):
    EFFECTIVE = "effective"
    PARTIAL = "partial"
    INEFFECTIVE = "ineffective"


# --- Models ---


class SoarResponseTrackerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    response_phase: ResponsePhase = ResponsePhase.CONTAINMENT
    automation_level: AutomationLevel = AutomationLevel.MANUAL
    response_effectiveness: ResponseEffectiveness = ResponseEffectiveness.EFFECTIVE
    score: float = 0.0
    response_time_seconds: float = 0.0
    playbook_name: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SoarResponseTrackerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    response_phase: ResponsePhase = ResponsePhase.CONTAINMENT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SoarResponseTrackerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_response_phase: dict[str, int] = Field(default_factory=dict)
    by_automation_level: dict[str, int] = Field(default_factory=dict)
    by_response_effectiveness: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class SoarResponseTrackerEngine:
    """Track SOAR response workflow execution metrics."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[SoarResponseTrackerRecord] = []
        self._analyses: list[SoarResponseTrackerAnalysis] = []
        logger.info(
            "soar_response_tracker_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        response_phase: ResponsePhase = ResponsePhase.CONTAINMENT,
        automation_level: AutomationLevel = AutomationLevel.MANUAL,
        response_effectiveness: ResponseEffectiveness = ResponseEffectiveness.EFFECTIVE,
        score: float = 0.0,
        response_time_seconds: float = 0.0,
        playbook_name: str = "",
        service: str = "",
        team: str = "",
    ) -> SoarResponseTrackerRecord:
        record = SoarResponseTrackerRecord(
            name=name,
            response_phase=response_phase,
            automation_level=automation_level,
            response_effectiveness=response_effectiveness,
            score=score,
            response_time_seconds=response_time_seconds,
            playbook_name=playbook_name,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "soar_response_tracker_engine.record_added",
            record_id=record.id,
            name=name,
            response_phase=response_phase.value,
            automation_level=automation_level.value,
        )
        return record

    def get_record(self, record_id: str) -> SoarResponseTrackerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        response_phase: ResponsePhase | None = None,
        automation_level: AutomationLevel | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[SoarResponseTrackerRecord]:
        results = list(self._records)
        if response_phase is not None:
            results = [r for r in results if r.response_phase == response_phase]
        if automation_level is not None:
            results = [r for r in results if r.automation_level == automation_level]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        response_phase: ResponsePhase = ResponsePhase.CONTAINMENT,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> SoarResponseTrackerAnalysis:
        analysis = SoarResponseTrackerAnalysis(
            name=name,
            response_phase=response_phase,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "soar_response_tracker_engine.analysis_added",
            name=name,
            response_phase=response_phase.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_mean_time_to_contain(self) -> list[dict[str, Any]]:
        """Compute mean time to contain (MTTC) per service."""
        svc_data: dict[str, list[SoarResponseTrackerRecord]] = {}
        for r in self._records:
            if r.response_phase == ResponsePhase.CONTAINMENT:
                svc_data.setdefault(r.service, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            times = [r.response_time_seconds for r in records]
            avg_time = round(sum(times) / len(times), 2) if times else 0.0
            results.append(
                {
                    "service": svc,
                    "mttc_seconds": avg_time,
                    "containment_count": len(records),
                    "effective_count": sum(
                        1
                        for r in records
                        if r.response_effectiveness == ResponseEffectiveness.EFFECTIVE
                    ),
                    "avg_score": round(sum(r.score for r in records) / len(records), 2),
                }
            )
        return sorted(results, key=lambda x: x["mttc_seconds"], reverse=True)

    def identify_slow_response_phases(self) -> list[dict[str, Any]]:
        """Identify response phases that are slower than average."""
        phase_times: dict[str, list[float]] = {}
        for r in self._records:
            phase_times.setdefault(r.response_phase.value, []).append(r.response_time_seconds)
        all_times = [r.response_time_seconds for r in self._records]
        overall_avg = sum(all_times) / len(all_times) if all_times else 0.0
        slow_phases: list[dict[str, Any]] = []
        for phase, times in phase_times.items():
            avg_time = round(sum(times) / len(times), 2)
            if avg_time > overall_avg:
                slow_phases.append(
                    {
                        "phase": phase,
                        "avg_response_time": avg_time,
                        "overall_avg": round(overall_avg, 2),
                        "slowdown_factor": round(avg_time / overall_avg, 2) if overall_avg else 0.0,
                        "record_count": len(times),
                    }
                )
        return sorted(slow_phases, key=lambda x: x["avg_response_time"], reverse=True)

    def recommend_automation_upgrades(self) -> list[dict[str, Any]]:
        """Recommend phases/services that should be automated."""
        recommendations: list[dict[str, Any]] = []
        manual_records = [r for r in self._records if r.automation_level == AutomationLevel.MANUAL]
        svc_manual: dict[str, list[SoarResponseTrackerRecord]] = {}
        for r in manual_records:
            svc_manual.setdefault(r.service, []).append(r)
        for svc, records in svc_manual.items():
            avg_time = round(sum(r.response_time_seconds for r in records) / len(records), 2)
            ineffective = sum(
                1 for r in records if r.response_effectiveness == ResponseEffectiveness.INEFFECTIVE
            )
            priority = (
                "high"
                if ineffective > 0 or avg_time > 3600
                else ("medium" if avg_time > 900 else "low")
            )
            recommendations.append(
                {
                    "service": svc,
                    "manual_count": len(records),
                    "avg_response_time": avg_time,
                    "ineffective_count": ineffective,
                    "priority": priority,
                    "suggestion": (
                        f"Automate {svc} response workflows — "
                        f"{len(records)} manual actions, avg {avg_time}s response time"
                    ),
                }
            )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else (1 if x["priority"] == "medium" else 2),
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.response_phase.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "response_phase": r.response_phase.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> SoarResponseTrackerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.response_phase.value] = by_e1.get(r.response_phase.value, 0) + 1
            by_e2[r.automation_level.value] = by_e2.get(r.automation_level.value, 0) + 1
            by_e3[r.response_effectiveness.value] = by_e3.get(r.response_effectiveness.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("SOAR Response Tracker Engine is healthy")
        return SoarResponseTrackerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_response_phase=by_e1,
            by_automation_level=by_e2,
            by_response_effectiveness=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("soar_response_tracker_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.response_phase.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "response_phase_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
