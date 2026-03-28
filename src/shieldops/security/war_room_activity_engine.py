"""War Room Activity Engine — log war room activities and decisions."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ActivityType(StrEnum):
    DECISION = "decision"
    TASK_ASSIGNMENT = "task_assignment"
    STATUS_UPDATE = "status_update"
    ESCALATION = "escalation"
    COMMUNICATION = "communication"


class ParticipantRole(StrEnum):
    INCIDENT_COMMANDER = "incident_commander"
    TECHNICAL_LEAD = "technical_lead"
    COMMUNICATIONS = "communications"
    LEGAL = "legal"
    EXECUTIVE = "executive"


class DecisionQuality(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ADEQUATE = "adequate"
    POOR = "poor"
    REVERSED = "reversed"


# --- Models ---


class ActivityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    war_room_id: str = ""
    activity_type: ActivityType = ActivityType.DECISION
    participant_role: ParticipantRole = ParticipantRole.INCIDENT_COMMANDER
    decision_quality: DecisionQuality = DecisionQuality.GOOD
    description: str = ""
    duration_min: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ActivityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    war_room_id: str = ""
    activity_type: ActivityType = ActivityType.DECISION
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ActivityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_duration_min: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_role: dict[str, int] = Field(default_factory=dict)
    by_quality: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class WarRoomActivityEngine:
    """Log and analyze war room activities."""

    def __init__(
        self,
        max_records: int = 200000,
        quality_threshold: float = 75.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = quality_threshold
        self._records: list[ActivityRecord] = []
        self._analyses: list[ActivityAnalysis] = []
        logger.info(
            "war_room_activity_engine.initialized",
            max_records=max_records,
        )

    # -- record / get / list ---

    def add_record(
        self,
        war_room_id: str,
        activity_type: ActivityType = (ActivityType.DECISION),
        participant_role: ParticipantRole = (ParticipantRole.INCIDENT_COMMANDER),
        decision_quality: DecisionQuality = (DecisionQuality.GOOD),
        description: str = "",
        duration_min: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ActivityRecord:
        record = ActivityRecord(
            war_room_id=war_room_id,
            activity_type=activity_type,
            participant_role=participant_role,
            decision_quality=decision_quality,
            description=description,
            duration_min=duration_min,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "war_room_activity_engine.record_added",
            record_id=record.id,
            war_room_id=war_room_id,
        )
        return record

    def get_record(self, record_id: str) -> ActivityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        activity_type: ActivityType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ActivityRecord]:
        results = list(self._records)
        if activity_type is not None:
            results = [r for r in results if r.activity_type == activity_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        war_room_id: str,
        activity_type: ActivityType = (ActivityType.DECISION),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ActivityAnalysis:
        analysis = ActivityAnalysis(
            war_room_id=war_room_id,
            activity_type=activity_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ---

    def log_activity(self) -> list[dict[str, Any]]:
        """Summarize activities by war room."""
        wr_data: dict[str, list[ActivityRecord]] = {}
        for r in self._records:
            wr_data.setdefault(r.war_room_id, []).append(r)
        results: list[dict[str, Any]] = []
        for wr_id, records in wr_data.items():
            durations = [r.duration_min for r in records]
            avg_dur = (
                round(
                    sum(durations) / len(durations),
                    2,
                )
                if durations
                else 0.0
            )
            results.append(
                {
                    "war_room_id": wr_id,
                    "total_activities": len(records),
                    "avg_duration_min": avg_dur,
                }
            )
        return sorted(
            results,
            key=lambda x: x["total_activities"],
            reverse=True,
        )

    def track_participation(
        self,
    ) -> list[dict[str, Any]]:
        """Track participation by role."""
        role_data: dict[str, list[ActivityRecord]] = {}
        for r in self._records:
            role_data.setdefault(r.participant_role.value, []).append(r)
        results: list[dict[str, Any]] = []
        for role, records in role_data.items():
            results.append(
                {
                    "role": role,
                    "count": len(records),
                    "unique_war_rooms": len({r.war_room_id for r in records}),
                }
            )
        return sorted(
            results,
            key=lambda x: x["count"],
            reverse=True,
        )

    def assess_decision_quality(
        self,
    ) -> list[dict[str, Any]]:
        """Assess decision quality distribution."""
        q_data: dict[str, list[ActivityRecord]] = {}
        for r in self._records:
            if r.activity_type == ActivityType.DECISION:
                q_data.setdefault(r.decision_quality.value, []).append(r)
        results: list[dict[str, Any]] = []
        for quality, records in q_data.items():
            results.append(
                {
                    "quality": quality,
                    "count": len(records),
                    "pct": round(
                        len(records) / max(len(self._records), 1) * 100,
                        2,
                    ),
                }
            )
        return sorted(
            results,
            key=lambda x: x["count"],
            reverse=True,
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.war_room_id == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
        }

    def generate_report(self) -> ActivityReport:
        by_type: dict[str, int] = {}
        by_role: dict[str, int] = {}
        by_quality: dict[str, int] = {}
        for r in self._records:
            by_type[r.activity_type.value] = by_type.get(r.activity_type.value, 0) + 1
            by_role[r.participant_role.value] = by_role.get(r.participant_role.value, 0) + 1
            by_quality[r.decision_quality.value] = by_quality.get(r.decision_quality.value, 0) + 1
        durations = [r.duration_min for r in self._records]
        avg_dur = round(sum(durations) / len(durations), 2) if durations else 0.0
        recs: list[str] = []
        poor = by_quality.get("poor", 0) + by_quality.get("reversed", 0)
        if self._records and poor > 0:
            recs.append(f"{poor} poor/reversed decisions")
        if not recs:
            recs.append("War Room Activity Engine is healthy")
        return ActivityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_duration_min=avg_dur,
            by_type=by_type,
            by_role=by_role,
            by_quality=by_quality,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("war_room_activity_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            k = r.activity_type.value
            type_dist[k] = type_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "quality_threshold": self._threshold,
            "type_distribution": type_dist,
            "unique_war_rooms": len({r.war_room_id for r in self._records}),
        }
