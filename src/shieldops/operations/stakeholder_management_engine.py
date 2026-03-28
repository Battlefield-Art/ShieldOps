"""Stakeholder Management Engine — route and track stakeholder comms."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class StakeholderCategory(StrEnum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    LEGAL = "legal"
    COMMUNICATIONS = "communications"
    CUSTOMER = "customer"


class ContactPreference(StrEnum):
    SLACK = "slack"
    EMAIL = "email"
    PHONE = "phone"
    SMS = "sms"
    IN_PERSON = "in_person"


class EscalationPath(StrEnum):
    DIRECT = "direct"
    MANAGER = "manager"
    VP = "vp"
    C_SUITE = "c_suite"
    BOARD = "board"


# --- Models ---


class StakeholderRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    stakeholder_name: str = ""
    category: StakeholderCategory = StakeholderCategory.TECHNICAL
    preference: ContactPreference = ContactPreference.SLACK
    escalation_path: EscalationPath = EscalationPath.DIRECT
    incident_id: str = ""
    engaged: bool = False
    response_time_sec: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class StakeholderAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    stakeholder_name: str = ""
    category: StakeholderCategory = StakeholderCategory.TECHNICAL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class StakeholderReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_response_sec: float = 0.0
    engagement_rate: float = 0.0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_preference: dict[str, int] = Field(default_factory=dict)
    by_escalation: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class StakeholderManagementEngine:
    """Route and track stakeholder engagement."""

    def __init__(
        self,
        max_records: int = 200000,
        response_threshold_sec: float = 600.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = response_threshold_sec
        self._records: list[StakeholderRecord] = []
        self._analyses: list[StakeholderAnalysis] = []
        logger.info(
            "stakeholder_management.initialized",
            max_records=max_records,
        )

    def record_item(
        self,
        stakeholder_name: str,
        category: StakeholderCategory = (StakeholderCategory.TECHNICAL),
        preference: ContactPreference = (ContactPreference.SLACK),
        escalation_path: EscalationPath = (EscalationPath.DIRECT),
        incident_id: str = "",
        engaged: bool = False,
        response_time_sec: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> StakeholderRecord:
        record = StakeholderRecord(
            stakeholder_name=stakeholder_name,
            category=category,
            preference=preference,
            escalation_path=escalation_path,
            incident_id=incident_id,
            engaged=engaged,
            response_time_sec=response_time_sec,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "stakeholder_management.record_added",
            record_id=record.id,
            stakeholder=stakeholder_name,
        )
        return record

    def get_record(self, record_id: str) -> StakeholderRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        category: StakeholderCategory | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[StakeholderRecord]:
        results = list(self._records)
        if category is not None:
            results = [r for r in results if r.category == category]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    # -- domain operations ---

    def identify_stakeholders(
        self,
    ) -> list[dict[str, Any]]:
        """Identify stakeholders by category."""
        cat_data: dict[str, list[StakeholderRecord]] = {}
        for r in self._records:
            cat_data.setdefault(r.category.value, []).append(r)
        results: list[dict[str, Any]] = []
        for cat, records in cat_data.items():
            engaged = sum(1 for r in records if r.engaged)
            results.append(
                {
                    "category": cat,
                    "total": len(records),
                    "engaged": engaged,
                    "engagement_rate": round(
                        engaged / len(records) * 100,
                        2,
                    )
                    if records
                    else 0.0,
                }
            )
        return sorted(
            results,
            key=lambda x: x["engagement_rate"],
        )

    def route_notification(
        self,
    ) -> list[dict[str, Any]]:
        """Analyze routing by preference."""
        pref_data: dict[str, list[StakeholderRecord]] = {}
        for r in self._records:
            pref_data.setdefault(r.preference.value, []).append(r)
        results: list[dict[str, Any]] = []
        for pref, records in pref_data.items():
            times = [r.response_time_sec for r in records if r.response_time_sec > 0]
            avg = round(sum(times) / len(times), 2) if times else 0.0
            results.append(
                {
                    "preference": pref,
                    "count": len(records),
                    "avg_response_sec": avg,
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_response_sec"],
        )

    def track_engagement(
        self,
    ) -> list[dict[str, Any]]:
        """Track engagement by escalation path."""
        esc_data: dict[str, list[StakeholderRecord]] = {}
        for r in self._records:
            esc_data.setdefault(r.escalation_path.value, []).append(r)
        results: list[dict[str, Any]] = []
        for path, records in esc_data.items():
            engaged = sum(1 for r in records if r.engaged)
            results.append(
                {
                    "escalation_path": path,
                    "total": len(records),
                    "engaged": engaged,
                }
            )
        return sorted(
            results,
            key=lambda x: x["total"],
            reverse=True,
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.stakeholder_name == key or r.incident_id == key]
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

    def generate_report(self) -> StakeholderReport:
        by_cat: dict[str, int] = {}
        by_pref: dict[str, int] = {}
        by_esc: dict[str, int] = {}
        for r in self._records:
            by_cat[r.category.value] = by_cat.get(r.category.value, 0) + 1
            by_pref[r.preference.value] = by_pref.get(r.preference.value, 0) + 1
            by_esc[r.escalation_path.value] = by_esc.get(r.escalation_path.value, 0) + 1
        times = [r.response_time_sec for r in self._records if r.response_time_sec > 0]
        avg_resp = round(sum(times) / len(times), 2) if times else 0.0
        engaged = sum(1 for r in self._records if r.engaged)
        rate = (
            round(
                engaged / len(self._records) * 100,
                2,
            )
            if self._records
            else 0.0
        )
        recs: list[str] = []
        if rate < 80:
            recs.append(f"Engagement {rate}% below 80%")
        if avg_resp > self._threshold:
            recs.append(f"Avg response {avg_resp}s exceeds {self._threshold}s")
        if not recs:
            recs.append("Stakeholder Management healthy")
        return StakeholderReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_response_sec=avg_resp,
            engagement_rate=rate,
            by_category=by_cat,
            by_preference=by_pref,
            by_escalation=by_esc,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("stakeholder_management.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        cat_dist: dict[str, int] = {}
        for r in self._records:
            k = r.category.value
            cat_dist[k] = cat_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "response_threshold": self._threshold,
            "category_distribution": cat_dist,
        }
