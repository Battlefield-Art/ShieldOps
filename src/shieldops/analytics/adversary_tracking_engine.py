"""Adversary Tracking Engine — track adversary groups, map campaigns, predict targets."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AdversaryGroup(StrEnum):
    APT28 = "apt28"
    APT29 = "apt29"
    LAZARUS = "lazarus"
    FIN7 = "fin7"
    UNKNOWN = "unknown"


class TTPFocus(StrEnum):
    INITIAL_ACCESS = "initial_access"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"


class TrackingStatus(StrEnum):
    ACTIVE = "active"
    DORMANT = "dormant"
    EMERGING = "emerging"
    RETIRED = "retired"
    UNKNOWN = "unknown"


# --- Models ---


class AdversaryRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    adversary_name: str = ""
    adversary_group: AdversaryGroup = AdversaryGroup.UNKNOWN
    ttp_focus: TTPFocus = TTPFocus.INITIAL_ACCESS
    tracking_status: TrackingStatus = TrackingStatus.ACTIVE
    threat_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AdversaryAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    adversary_name: str = ""
    adversary_group: AdversaryGroup = AdversaryGroup.UNKNOWN
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AdversaryReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    active_count: int = 0
    avg_threat_score: float = 0.0
    by_group: dict[str, int] = Field(default_factory=dict)
    by_ttp: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    top_threats: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AdversaryTrackingEngine:
    """Track adversary groups, map campaign activity, predict next targets."""

    def __init__(
        self,
        max_records: int = 200000,
        threat_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threat_threshold = threat_threshold
        self._records: list[AdversaryRecord] = []
        self._analyses: list[AdversaryAnalysis] = []
        logger.info(
            "adversary_tracking.initialized",
            max_records=max_records,
            threat_threshold=threat_threshold,
        )

    # -- record / get / list ----------------------------

    def add_record(
        self,
        adversary_name: str,
        adversary_group: AdversaryGroup = (AdversaryGroup.UNKNOWN),
        ttp_focus: TTPFocus = TTPFocus.INITIAL_ACCESS,
        tracking_status: TrackingStatus = (TrackingStatus.ACTIVE),
        threat_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> AdversaryRecord:
        record = AdversaryRecord(
            adversary_name=adversary_name,
            adversary_group=adversary_group,
            ttp_focus=ttp_focus,
            tracking_status=tracking_status,
            threat_score=threat_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "adversary_tracking.record_added",
            record_id=record.id,
            adversary_name=adversary_name,
            adversary_group=adversary_group.value,
        )
        return record

    def get_record(self, record_id: str) -> AdversaryRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        adversary_group: AdversaryGroup | None = None,
        tracking_status: TrackingStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AdversaryRecord]:
        results = list(self._records)
        if adversary_group is not None:
            results = [r for r in results if r.adversary_group == adversary_group]
        if tracking_status is not None:
            results = [r for r in results if r.tracking_status == tracking_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        adversary_name: str,
        adversary_group: AdversaryGroup = (AdversaryGroup.UNKNOWN),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AdversaryAnalysis:
        analysis = AdversaryAnalysis(
            adversary_name=adversary_name,
            adversary_group=adversary_group,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "adversary_tracking.analysis_added",
            adversary_name=adversary_name,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ------------------------------

    def track_adversary(self) -> dict[str, Any]:
        """Group by adversary_group; return count and avg threat_score."""
        group_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.adversary_group.value
            group_data.setdefault(key, []).append(r.threat_score)
        result: dict[str, Any] = {}
        for group, scores in group_data.items():
            result[group] = {
                "count": len(scores),
                "avg_threat_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def map_campaign_activity(
        self,
    ) -> list[dict[str, Any]]:
        """Return active adversaries above threat threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if (
                r.tracking_status == TrackingStatus.ACTIVE
                and r.threat_score >= self._threat_threshold
            ):
                results.append(
                    {
                        "record_id": r.id,
                        "adversary_name": (r.adversary_name),
                        "adversary_group": (r.adversary_group.value),
                        "ttp_focus": (r.ttp_focus.value),
                        "threat_score": (r.threat_score),
                        "service": r.service,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["threat_score"],
            reverse=True,
        )

    def predict_next_target(
        self,
    ) -> list[dict[str, Any]]:
        """Group by service, count active hits, sort descending."""
        svc_counts: dict[str, int] = {}
        for r in self._records:
            if r.tracking_status == TrackingStatus.ACTIVE:
                svc_counts[r.service] = svc_counts.get(r.service, 0) + 1
        results = [{"service": svc, "active_hits": cnt} for svc, cnt in svc_counts.items()]
        results.sort(
            key=lambda x: x["active_hits"],
            reverse=True,
        )
        return results

    # -- report / stats ---------------------------------

    def generate_report(self) -> AdversaryReport:
        by_group: dict[str, int] = {}
        by_ttp: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for r in self._records:
            by_group[r.adversary_group.value] = by_group.get(r.adversary_group.value, 0) + 1
            by_ttp[r.ttp_focus.value] = by_ttp.get(r.ttp_focus.value, 0) + 1
            by_status[r.tracking_status.value] = by_status.get(r.tracking_status.value, 0) + 1
        active_count = sum(1 for r in self._records if r.tracking_status == TrackingStatus.ACTIVE)
        scores = [r.threat_score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        top = [
            r.adversary_name
            for r in sorted(
                self._records,
                key=lambda x: x.threat_score,
                reverse=True,
            )[:5]
        ]
        recs: list[str] = []
        if active_count > 0:
            recs.append(f"{active_count} active adversary group(s) being tracked")
        if not recs:
            recs.append("No active adversary tracking alerts")
        return AdversaryReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            active_count=active_count,
            avg_threat_score=avg,
            by_group=by_group,
            by_ttp=by_ttp,
            by_status=by_status,
            top_threats=top,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("adversary_tracking.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        group_dist: dict[str, int] = {}
        for r in self._records:
            key = r.adversary_group.value
            group_dist[key] = group_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threat_threshold": (self._threat_threshold),
            "group_distribution": group_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
