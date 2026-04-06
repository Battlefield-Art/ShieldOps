"""Access Review Campaign Engine — track access review campaign progress and outcomes."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AccessReviewCampaignEngine = engine(
    "AccessReviewCampaignEngine",
    description="Track access review campaign progress, outcomes, and entitlement risk.",
    enums={
        "campaign_status": EnumDef(
            "CampaignStatus",
            {
                "PLANNED": "planned",
                "ACTIVE": "active",
                "REVIEW": "review",
                "CLOSED": "closed",
                "OVERDUE": "overdue",
            },
        ),
        "review_outcome": EnumDef(
            "ReviewOutcome",
            {
                "CERTIFIED": "certified",
                "REVOKED": "revoked",
                "MODIFIED": "modified",
                "ESCALATED": "escalated",
                "DEFERRED": "deferred",
            },
        ),
        "entitlement_risk": EnumDef(
            "EntitlementRisk",
            {
                "EXCESSIVE": "excessive",
                "UNUSED": "unused",
                "SOD_VIOLATION": "sod_violation",
                "ORPHANED": "orphaned",
                "APPROPRIATE": "appropriate",
            },
        ),
    },
    record_fields=[
        FieldDef("reviewer", str, ""),
        FieldDef("reviews_completed", int, 0),
        FieldDef("reviews_pending", int, 0),
    ],
    key_field="campaign_id",
)

# Backward-compatible re-exports
CampaignStatus = AccessReviewCampaignEngine.CampaignStatus
ReviewOutcome = AccessReviewCampaignEngine.ReviewOutcome
EntitlementRisk = AccessReviewCampaignEngine.EntitlementRisk
AccessReviewCampaignRecord = AccessReviewCampaignEngine.Record
AccessReviewCampaignAnalysis = AccessReviewCampaignEngine.Analysis
AccessReviewCampaignReport = AccessReviewCampaignEngine.Report
