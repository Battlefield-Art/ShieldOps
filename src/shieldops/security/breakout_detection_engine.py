"""Breakout Detection Engine — breakout time and containment."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BreakoutStage(StrEnum):
    INITIAL_ACCESS = "initial_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_ACCESS = "data_access"
    EXFILTRATION = "exfiltration"


class ContainmentSpeed(StrEnum):
    SUB_MINUTE = "sub_minute"
    MINUTES = "minutes"
    HOURS = "hours"
    DAYS = "days"
    UNCONTAINED = "uncontained"


class DefenseOutcome(StrEnum):
    CONTAINED = "contained"
    PARTIAL = "partial"
    ESCAPED = "escaped"
    DETECTED_LATE = "detected_late"
    MISSED = "missed"


# --- Models ---


class BreakoutRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    stage: BreakoutStage = BreakoutStage.INITIAL_ACCESS
    speed: ContainmentSpeed = ContainmentSpeed.MINUTES
    outcome: DefenseOutcome = DefenseOutcome.CONTAINED
    breakout_time_seconds: float = 0.0
    response_time_seconds: float = 0.0
    attacker_ttp: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class BreakoutAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    stage: BreakoutStage = BreakoutStage.INITIAL_ACCESS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BreakoutReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_breakout_time: float = 0.0
    avg_response_time: float = 0.0
    containment_rate: float = 0.0
    by_stage: dict[str, int] = Field(default_factory=dict)
    by_speed: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class BreakoutDetectionEngine:
    """Track breakout time and containment speed."""

    def __init__(
        self,
        max_records: int = 200000,
        response_threshold: float = 60.0,
    ) -> None:
        self._max_records = max_records
        self._response_threshold = response_threshold
        self._records: list[BreakoutRecord] = []
        self._analyses: list[BreakoutAnalysis] = []
        logger.info(
            "breakout_detection_engine.init",
            max_records=max_records,
        )

    # -- record --

    def add_record(
        self,
        incident_id: str = "",
        stage: BreakoutStage = (BreakoutStage.INITIAL_ACCESS),
        speed: ContainmentSpeed = (ContainmentSpeed.MINUTES),
        outcome: DefenseOutcome = (DefenseOutcome.CONTAINED),
        breakout_time_seconds: float = 0.0,
        response_time_seconds: float = 0.0,
        attacker_ttp: str = "",
        service: str = "",
        team: str = "",
    ) -> BreakoutRecord:
        record = BreakoutRecord(
            incident_id=incident_id,
            stage=stage,
            speed=speed,
            outcome=outcome,
            breakout_time_seconds=(breakout_time_seconds),
            response_time_seconds=(response_time_seconds),
            attacker_ttp=attacker_ttp,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "breakout_detection.record_added",
            record_id=record.id,
        )
        return record

    # -- process --

    def process(self, incident_id: str) -> BreakoutAnalysis:
        relevant = [r for r in self._records if r.incident_id == incident_id]
        if not relevant:
            analysis = BreakoutAnalysis(
                incident_id=incident_id,
                description="no records found",
            )
            self._analyses.append(analysis)
            return analysis
        resp_times = [r.response_time_seconds for r in relevant]
        avg_resp = sum(resp_times) / len(resp_times)
        breached = avg_resp > self._response_threshold
        analysis = BreakoutAnalysis(
            incident_id=incident_id,
            analysis_score=round(avg_resp, 2),
            threshold=self._response_threshold,
            breached=breached,
            description=(f"avg_response={round(avg_resp, 2)}s"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain methods --

    def track_breakout_attempt(
        self,
    ) -> dict[str, Any]:
        """Breakout stats by stage."""
        stage_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.stage.value
            stage_data.setdefault(key, []).append(r.breakout_time_seconds)
        result: dict[str, Any] = {}
        for stage, times in stage_data.items():
            result[stage] = {
                "count": len(times),
                "avg_breakout_time": round(sum(times) / len(times), 2),
            }
        return result

    def measure_response_time(
        self,
    ) -> dict[str, Any]:
        """Response time distribution by speed."""
        speed_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.speed.value
            speed_data.setdefault(key, []).append(r.response_time_seconds)
        result: dict[str, Any] = {}
        for speed, times in speed_data.items():
            result[speed] = {
                "count": len(times),
                "avg_response": round(sum(times) / len(times), 2),
            }
        return result

    def predict_breakout_risk(
        self,
    ) -> list[dict[str, Any]]:
        """Identify high-risk TTPs by outcome."""
        ttp_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            if r.attacker_ttp:
                ttp_data.setdefault(
                    r.attacker_ttp,
                    {"total": 0, "escaped": 0},
                )
                ttp_data[r.attacker_ttp]["total"] += 1
                if r.outcome == DefenseOutcome.ESCAPED:
                    ttp_data[r.attacker_ttp]["escaped"] += 1
        results: list[dict[str, Any]] = []
        for ttp, data in ttp_data.items():
            escape_rate = 0.0
            if data["total"] > 0:
                escape_rate = data["escaped"] / data["total"] * 100
            results.append(
                {
                    "ttp": ttp,
                    "escape_rate": round(escape_rate, 2),
                    "total": data["total"],
                    "risk": ("high" if escape_rate > 30 else "low"),
                }
            )
        return sorted(
            results,
            key=lambda x: x["escape_rate"],
            reverse=True,
        )

    # -- report / stats --

    def generate_report(self) -> BreakoutReport:
        by_stage: dict[str, int] = {}
        by_speed: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        for r in self._records:
            by_stage[r.stage.value] = by_stage.get(r.stage.value, 0) + 1
            by_speed[r.speed.value] = by_speed.get(r.speed.value, 0) + 1
            by_outcome[r.outcome.value] = by_outcome.get(r.outcome.value, 0) + 1
        bt = [r.breakout_time_seconds for r in self._records]
        rt = [r.response_time_seconds for r in self._records]
        avg_bt = round(sum(bt) / len(bt), 2) if bt else 0.0
        avg_rt = round(sum(rt) / len(rt), 2) if rt else 0.0
        contained = sum(1 for r in self._records if r.outcome == DefenseOutcome.CONTAINED)
        cont_rate = (
            round(
                contained / len(self._records) * 100,
                2,
            )
            if self._records
            else 0.0
        )
        recs: list[str] = []
        if avg_rt > self._response_threshold:
            recs.append(f"Avg response {avg_rt}s exceeds {self._response_threshold}s")
        if cont_rate < 80.0:
            recs.append(f"Containment rate {cont_rate}% below 80%")
        if not recs:
            recs.append("Breakout detection is healthy")
        return BreakoutReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_breakout_time=avg_bt,
            avg_response_time=avg_rt,
            containment_rate=cont_rate,
            by_stage=by_stage,
            by_speed=by_speed,
            by_outcome=by_outcome,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "response_threshold": (self._response_threshold),
            "unique_incidents": len({r.incident_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("breakout_detection_engine.cleared")
        return {"status": "cleared"}
