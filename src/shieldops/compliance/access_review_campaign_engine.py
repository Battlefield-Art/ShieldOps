"""Access Review Campaign Engine — track access review campaign progress and outcomes."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CampaignStatus(StrEnum):
    PLANNED = "planned"
    ACTIVE = "active"
    REVIEW = "review"
    CLOSED = "closed"
    OVERDUE = "overdue"


class ReviewOutcome(StrEnum):
    CERTIFIED = "certified"
    REVOKED = "revoked"
    MODIFIED = "modified"
    ESCALATED = "escalated"
    DEFERRED = "deferred"


class EntitlementRisk(StrEnum):
    EXCESSIVE = "excessive"
    UNUSED = "unused"
    SOD_VIOLATION = "sod_violation"
    ORPHANED = "orphaned"
    APPROPRIATE = "appropriate"


# --- Models ---


class AccessReviewCampaignRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_id: str = ""
    campaign_status: CampaignStatus = CampaignStatus.PLANNED
    review_outcome: ReviewOutcome = ReviewOutcome.CERTIFIED
    entitlement_risk: EntitlementRisk = EntitlementRisk.APPROPRIATE
    reviewer: str = ""
    reviews_completed: int = 0
    reviews_pending: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AccessReviewCampaignAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_id: str = ""
    campaign_status: CampaignStatus = CampaignStatus.PLANNED
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AccessReviewCampaignReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_campaign_status: dict[str, int] = Field(default_factory=dict)
    by_review_outcome: dict[str, int] = Field(default_factory=dict)
    by_entitlement_risk: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AccessReviewCampaignEngine:
    """Track access review campaign progress, outcomes, and entitlement risk."""

    def __init__(
        self,
        max_records: int = 200000,
        completion_threshold: float = 95.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = completion_threshold
        self._records: list[AccessReviewCampaignRecord] = []
        self._analyses: list[AccessReviewCampaignAnalysis] = []
        logger.info(
            "access_review_campaign_engine.initialized",
            max_records=max_records,
            completion_threshold=completion_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        campaign_id: str,
        campaign_status: CampaignStatus = CampaignStatus.PLANNED,
        review_outcome: ReviewOutcome = ReviewOutcome.CERTIFIED,
        entitlement_risk: EntitlementRisk = EntitlementRisk.APPROPRIATE,
        reviewer: str = "",
        reviews_completed: int = 0,
        reviews_pending: int = 0,
        service: str = "",
        team: str = "",
    ) -> AccessReviewCampaignRecord:
        record = AccessReviewCampaignRecord(
            campaign_id=campaign_id,
            campaign_status=campaign_status,
            review_outcome=review_outcome,
            entitlement_risk=entitlement_risk,
            reviewer=reviewer,
            reviews_completed=reviews_completed,
            reviews_pending=reviews_pending,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "access_review_campaign_engine.record_added",
            record_id=record.id,
            campaign_id=campaign_id,
            campaign_status=campaign_status.value,
            review_outcome=review_outcome.value,
        )
        return record

    def get_record(self, record_id: str) -> AccessReviewCampaignRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        campaign_status: CampaignStatus | None = None,
        review_outcome: ReviewOutcome | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AccessReviewCampaignRecord]:
        results = list(self._records)
        if campaign_status is not None:
            results = [r for r in results if r.campaign_status == campaign_status]
        if review_outcome is not None:
            results = [r for r in results if r.review_outcome == review_outcome]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        campaign_id: str,
        campaign_status: CampaignStatus = CampaignStatus.PLANNED,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AccessReviewCampaignAnalysis:
        analysis = AccessReviewCampaignAnalysis(
            campaign_id=campaign_id,
            campaign_status=campaign_status,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "access_review_campaign_engine.analysis_added",
            campaign_id=campaign_id,
            campaign_status=campaign_status.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_campaign_progress(self) -> list[dict[str, Any]]:
        """Analyze campaign progress by status and completion rate."""
        campaign_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            cid = r.campaign_id or "unknown"
            campaign_data.setdefault(cid, {"completed": 0, "pending": 0, "status": ""})
            campaign_data[cid]["completed"] += r.reviews_completed
            campaign_data[cid]["pending"] += r.reviews_pending
            campaign_data[cid]["status"] = r.campaign_status.value
        results: list[dict[str, Any]] = []
        for cid, stats in campaign_data.items():
            total = stats["completed"] + stats["pending"]
            completion_pct = round(stats["completed"] / total * 100, 2) if total > 0 else 0.0
            results.append(
                {
                    "campaign_id": cid,
                    "campaign_status": stats["status"],
                    "reviews_completed": stats["completed"],
                    "reviews_pending": stats["pending"],
                    "completion_pct": completion_pct,
                    "meets_threshold": completion_pct >= self._threshold,
                }
            )
        return sorted(results, key=lambda x: x["completion_pct"])

    def identify_overdue_reviews(self) -> list[dict[str, Any]]:
        """Identify overdue campaigns and pending reviews."""
        overdue: list[dict[str, Any]] = []
        for r in self._records:
            if r.campaign_status == CampaignStatus.OVERDUE or (
                r.reviews_pending > 0 and r.campaign_status == CampaignStatus.ACTIVE
            ):
                total = r.reviews_completed + r.reviews_pending
                completion_pct = round(r.reviews_completed / total * 100, 2) if total > 0 else 0.0
                overdue.append(
                    {
                        "record_id": r.id,
                        "campaign_id": r.campaign_id,
                        "campaign_status": r.campaign_status.value,
                        "reviewer": r.reviewer,
                        "reviews_pending": r.reviews_pending,
                        "completion_pct": completion_pct,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(overdue, key=lambda x: x["reviews_pending"], reverse=True)

    def detect_review_trends(self) -> list[dict[str, Any]]:
        """Detect review outcome trends by entitlement risk."""
        risk_outcomes: dict[str, dict[str, int]] = {}
        for r in self._records:
            risk = r.entitlement_risk.value
            risk_outcomes.setdefault(risk, {})
            outcome = r.review_outcome.value
            risk_outcomes[risk][outcome] = risk_outcomes[risk].get(outcome, 0) + 1
        results: list[dict[str, Any]] = []
        for risk, outcomes in risk_outcomes.items():
            total = sum(outcomes.values())
            revoked_pct = round(outcomes.get("revoked", 0) / total * 100, 2) if total > 0 else 0.0
            results.append(
                {
                    "entitlement_risk": risk,
                    "outcome_distribution": outcomes,
                    "total_reviews": total,
                    "revoked_pct": revoked_pct,
                    "escalated_count": outcomes.get("escalated", 0),
                }
            )
        return sorted(results, key=lambda x: x["revoked_pct"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def generate_report(self) -> AccessReviewCampaignReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.campaign_status.value] = by_e1.get(r.campaign_status.value, 0) + 1
            by_e2[r.review_outcome.value] = by_e2.get(r.review_outcome.value, 0) + 1
            by_e3[r.entitlement_risk.value] = by_e3.get(r.entitlement_risk.value, 0) + 1
        total_completed = sum(r.reviews_completed for r in self._records)
        total_pending = sum(r.reviews_pending for r in self._records)
        grand_total = total_completed + total_pending
        avg_score = round(total_completed / grand_total * 100, 2) if grand_total > 0 else 0.0
        overdue = self.identify_overdue_reviews()
        gap_count = len(overdue)
        top_gaps = [o["campaign_id"] for o in overdue[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} campaign(s) overdue or with pending reviews")
        if avg_score < self._threshold:
            recs.append(f"Overall completion {avg_score}% below threshold ({self._threshold}%)")
        if not recs:
            recs.append("Access Review Campaign Engine is healthy")
        return AccessReviewCampaignReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_campaign_status=by_e1,
            by_review_outcome=by_e2,
            by_entitlement_risk=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("access_review_campaign_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.campaign_status.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "completion_threshold": self._threshold,
            "campaign_status_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
