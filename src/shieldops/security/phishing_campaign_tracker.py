"""PhishingCampaignTracker — Track phishing simulations."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CampaignPhase(StrEnum):
    PLANNING = "planning"
    ACTIVE = "active"
    MONITORING = "monitoring"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class EmployeeAction(StrEnum):
    NO_ACTION = "no_action"
    OPENED_EMAIL = "opened_email"
    CLICKED_LINK = "clicked_link"
    SUBMITTED_CREDS = "submitted_creds"
    REPORTED = "reported"
    FORWARDED = "forwarded"


class AwarenessLevel(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    MODERATE = "moderate"
    POOR = "poor"
    CRITICAL = "critical"


# --- Models ---


class PhishingCampaignRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_name: str = ""
    phase: CampaignPhase = CampaignPhase.PLANNING
    action: EmployeeAction = EmployeeAction.NO_ACTION
    awareness: AwarenessLevel = AwarenessLevel.MODERATE
    score: float = 0.0
    department: str = ""
    employee_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class PhishingCampaignAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_name: str = ""
    phase: CampaignPhase = CampaignPhase.PLANNING
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PhishingCampaignReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_phase: dict[str, int] = Field(default_factory=dict)
    by_action: dict[str, int] = Field(default_factory=dict)
    by_awareness: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class PhishingCampaignTracker:
    """Track phishing simulation campaigns."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[PhishingCampaignRecord] = []
        self._analyses: list[PhishingCampaignAnalysis] = []
        logger.info(
            "phishing_campaign_tracker.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def add_record(
        self,
        campaign_name: str,
        phase: CampaignPhase = CampaignPhase.PLANNING,
        action: EmployeeAction = (EmployeeAction.NO_ACTION),
        awareness: AwarenessLevel = (AwarenessLevel.MODERATE),
        score: float = 0.0,
        department: str = "",
        employee_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> PhishingCampaignRecord:
        record = PhishingCampaignRecord(
            campaign_name=campaign_name,
            phase=phase,
            action=action,
            awareness=awareness,
            score=score,
            department=department,
            employee_count=employee_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "phishing_campaign_tracker.record_added",
            record_id=record.id,
            campaign_name=campaign_name,
            phase=phase.value,
        )
        return record

    def get_record(self, record_id: str) -> PhishingCampaignRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        phase: CampaignPhase | None = None,
        action: EmployeeAction | None = None,
        limit: int = 50,
    ) -> list[PhishingCampaignRecord]:
        results = list(self._records)
        if phase is not None:
            results = [r for r in results if r.phase == phase]
        if action is not None:
            results = [r for r in results if r.action == action]
        return results[-limit:]

    # -- domain operations --------------------------------

    def track_campaign(self, campaign_name: str) -> dict[str, Any]:
        """Track a specific campaign."""
        matched = [r for r in self._records if r.campaign_name == campaign_name]
        if not matched:
            return {
                "campaign": campaign_name,
                "status": "not_found",
            }
        actions: dict[str, int] = {}
        for r in matched:
            k = r.action.value
            actions[k] = actions.get(k, 0) + 1
        return {
            "campaign": campaign_name,
            "total_records": len(matched),
            "action_distribution": actions,
            "phase": matched[-1].phase.value,
        }

    def measure_click_rate(
        self,
    ) -> dict[str, Any]:
        """Measure click-through rate across campaigns."""
        total = len(self._records)
        if total == 0:
            return {
                "click_rate": 0.0,
                "report_rate": 0.0,
            }
        clicked = sum(
            1
            for r in self._records
            if r.action
            in (
                EmployeeAction.CLICKED_LINK,
                EmployeeAction.SUBMITTED_CREDS,
            )
        )
        reported = sum(1 for r in self._records if r.action == EmployeeAction.REPORTED)
        return {
            "total": total,
            "click_rate": round(clicked / total, 3),
            "submit_rate": round(
                sum(1 for r in self._records if r.action == EmployeeAction.SUBMITTED_CREDS) / total,
                3,
            ),
            "report_rate": round(reported / total, 3),
        }

    def identify_high_risk_departments(
        self,
    ) -> list[dict[str, Any]]:
        """Identify departments with poor awareness."""
        dept_stats: dict[str, dict[str, int]] = {}
        for r in self._records:
            if not r.department:
                continue
            d = dept_stats.setdefault(
                r.department,
                {"total": 0, "clicked": 0},
            )
            d["total"] += 1
            if r.action in (
                EmployeeAction.CLICKED_LINK,
                EmployeeAction.SUBMITTED_CREDS,
            ):
                d["clicked"] += 1
        results: list[dict[str, Any]] = []
        for dept, stats in dept_stats.items():
            rate = (
                round(
                    stats["clicked"] / stats["total"],
                    3,
                )
                if stats["total"] > 0
                else 0.0
            )
            results.append(
                {
                    "department": dept,
                    "total": stats["total"],
                    "clicked": stats["clicked"],
                    "click_rate": rate,
                    "risk": ("high" if rate > 0.3 else "medium" if rate > 0.1 else "low"),
                }
            )
        return sorted(
            results,
            key=lambda x: x["click_rate"],
            reverse=True,
        )

    # -- standard methods ---------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.campaign_name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
        }

    def generate_report(
        self,
    ) -> PhishingCampaignReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.phase.value] = by_e1.get(r.phase.value, 0) + 1
            by_e2[r.action.value] = by_e2.get(r.action.value, 0) + 1
            by_e3[r.awareness.value] = by_e3.get(r.awareness.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_ct = sum(1 for r in self._records if r.score < self._threshold)
        recs: list[str] = []
        if gap_ct > 0:
            recs.append(f"{gap_ct} campaign(s) need attention")
        if not recs:
            recs.append("Phishing campaign tracker healthy")
        return PhishingCampaignReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_ct,
            avg_score=avg,
            by_phase=by_e1,
            by_action=by_e2,
            by_awareness=by_e3,
            top_gaps=[],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.phase.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "phase_distribution": dist,
            "unique_campaigns": len({r.campaign_name for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("phishing_campaign_tracker.cleared")
        return {"status": "cleared"}
