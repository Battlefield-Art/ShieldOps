"""Response Approval Workflow — configurable approval chains for SOC response actions."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ApprovalTier(StrEnum):
    AUTO_EXECUTE = "auto_execute"
    TIER_1 = "tier_1"
    TIER_2 = "tier_2"
    TIER_3 = "tier_3"
    CISO = "ciso"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    AUTO_APPROVED = "auto_approved"


class NotificationChannel(StrEnum):
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"
    WEBHOOK = "webhook"


# --- Models ---


class ApprovalRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    situation_id: str = ""
    action_id: str = ""
    action_description: str = ""
    required_tier: ApprovalTier = ApprovalTier.TIER_1
    confidence: float = 0.0
    severity: str = "medium"
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: float = Field(default_factory=time.time)
    responded_at: float | None = None
    responder: str = ""
    rejection_reason: str = ""
    notification_channels: list[NotificationChannel] = Field(default_factory=list)


class ApprovalPolicy(BaseModel):
    min_confidence_auto: float = 0.85
    min_confidence_tier1: float = 0.7
    max_wait_minutes: int = 30
    fallback_tier: ApprovalTier = ApprovalTier.TIER_2
    escalation_after_minutes: int = 15
    default_channels: list[NotificationChannel] = Field(
        default_factory=lambda: [NotificationChannel.SLACK, NotificationChannel.EMAIL]
    )


class ApprovalReport(BaseModel):
    total_requests: int = 0
    auto_approved: int = 0
    manually_approved: int = 0
    rejected: int = 0
    expired: int = 0
    pending: int = 0
    avg_response_time_seconds: float = 0.0
    by_tier: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


_TIER_ORDER: list[ApprovalTier] = [
    ApprovalTier.AUTO_EXECUTE,
    ApprovalTier.TIER_1,
    ApprovalTier.TIER_2,
    ApprovalTier.TIER_3,
    ApprovalTier.CISO,
]

_SEVERITY_TIER_FLOOR: dict[str, ApprovalTier] = {
    "critical": ApprovalTier.TIER_3,
    "high": ApprovalTier.TIER_2,
    "medium": ApprovalTier.TIER_1,
    "low": ApprovalTier.TIER_1,
    "info": ApprovalTier.AUTO_EXECUTE,
}


class ResponseApprovalWorkflow:
    """Configurable approval chains for SOC response actions."""

    def __init__(
        self,
        max_records: int = 200000,
        policy: ApprovalPolicy | None = None,
    ) -> None:
        self._max_records = max_records
        self._policy = policy or ApprovalPolicy()
        self._records: list[ApprovalRecord] = []
        logger.info(
            "response_approval_workflow.initialized",
            max_records=max_records,
            min_confidence_auto=self._policy.min_confidence_auto,
        )

    def _determine_tier(self, confidence: float, severity: str) -> ApprovalTier:
        """Route to the correct approval tier based on confidence and severity."""
        if confidence >= self._policy.min_confidence_auto and severity not in (
            "critical",
            "high",
        ):
            return ApprovalTier.AUTO_EXECUTE
        severity_floor = _SEVERITY_TIER_FLOOR.get(severity, ApprovalTier.TIER_1)
        if confidence >= self._policy.min_confidence_tier1:
            confidence_tier = ApprovalTier.TIER_1
        elif confidence >= 0.5:
            confidence_tier = ApprovalTier.TIER_2
        else:
            confidence_tier = ApprovalTier.TIER_3
        floor_idx = _TIER_ORDER.index(severity_floor)
        conf_idx = _TIER_ORDER.index(confidence_tier)
        return _TIER_ORDER[max(floor_idx, conf_idx)]

    def _next_tier(self, tier: ApprovalTier) -> ApprovalTier:
        idx = _TIER_ORDER.index(tier)
        if idx < len(_TIER_ORDER) - 1:
            return _TIER_ORDER[idx + 1]
        return tier

    # -- approval lifecycle ---------------------------------------------------

    def request_approval(
        self,
        situation_id: str,
        action_id: str,
        action_description: str,
        confidence: float = 0.0,
        severity: str = "medium",
        notification_channels: list[NotificationChannel] | None = None,
    ) -> ApprovalRecord:
        tier = self._determine_tier(confidence, severity)
        channels = notification_channels or list(self._policy.default_channels)
        status = (
            ApprovalStatus.AUTO_APPROVED
            if tier == ApprovalTier.AUTO_EXECUTE
            else ApprovalStatus.PENDING
        )
        record = ApprovalRecord(
            situation_id=situation_id,
            action_id=action_id,
            action_description=action_description,
            required_tier=tier,
            confidence=confidence,
            severity=severity,
            status=status,
            notification_channels=channels,
            responded_at=time.time() if status == ApprovalStatus.AUTO_APPROVED else None,
            responder="system" if status == ApprovalStatus.AUTO_APPROVED else "",
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "response_approval_workflow.requested",
            record_id=record.id,
            situation_id=situation_id,
            tier=tier.value,
            status=status.value,
            confidence=confidence,
            severity=severity,
        )
        return record

    def approve(self, approval_id: str, responder: str) -> ApprovalRecord | None:
        record = self._find(approval_id)
        if record is None or record.status != ApprovalStatus.PENDING:
            return None
        record.status = ApprovalStatus.APPROVED
        record.responder = responder
        record.responded_at = time.time()
        logger.info(
            "response_approval_workflow.approved",
            record_id=approval_id,
            responder=responder,
        )
        return record

    def reject(self, approval_id: str, responder: str, reason: str = "") -> ApprovalRecord | None:
        record = self._find(approval_id)
        if record is None or record.status != ApprovalStatus.PENDING:
            return None
        record.status = ApprovalStatus.REJECTED
        record.responder = responder
        record.rejection_reason = reason
        record.responded_at = time.time()
        logger.info(
            "response_approval_workflow.rejected",
            record_id=approval_id,
            responder=responder,
            reason=reason,
        )
        return record

    def check_expirations(self) -> list[ApprovalRecord]:
        """Escalate expired pending approvals to the next tier."""
        now = time.time()
        escalated: list[ApprovalRecord] = []
        for r in self._records:
            if r.status != ApprovalStatus.PENDING:
                continue
            elapsed_min = (now - r.requested_at) / 60.0
            if elapsed_min >= self._policy.max_wait_minutes:
                r.status = ApprovalStatus.EXPIRED
                r.responded_at = now
                logger.info("response_approval_workflow.expired", record_id=r.id)
                new_tier = self._next_tier(r.required_tier)
                if new_tier != r.required_tier:
                    escalated_record = self.request_approval(
                        situation_id=r.situation_id,
                        action_id=r.action_id,
                        action_description=f"[ESCALATED] {r.action_description}",
                        confidence=r.confidence,
                        severity=r.severity,
                        notification_channels=r.notification_channels,
                    )
                    escalated_record.required_tier = new_tier
                    escalated.append(escalated_record)
        return escalated

    def get_pending(self, tier: ApprovalTier | None = None) -> list[ApprovalRecord]:
        results = [r for r in self._records if r.status == ApprovalStatus.PENDING]
        if tier is not None:
            results = [r for r in results if r.required_tier == tier]
        return results

    # -- domain operations ----------------------------------------------------

    def get_approval_latency_stats(self) -> dict[str, Any]:
        """Compute latency statistics for responded approvals."""
        latencies: list[float] = []
        for r in self._records:
            if r.responded_at is not None and r.status in (
                ApprovalStatus.APPROVED,
                ApprovalStatus.REJECTED,
            ):
                latencies.append(r.responded_at - r.requested_at)
        if not latencies:
            return {"avg_seconds": 0.0, "max_seconds": 0.0, "count": 0}
        return {
            "avg_seconds": round(sum(latencies) / len(latencies), 2),
            "max_seconds": round(max(latencies), 2),
            "count": len(latencies),
        }

    def get_rejection_reasons(self) -> list[dict[str, Any]]:
        """Aggregate rejection reasons."""
        reasons: dict[str, int] = {}
        for r in self._records:
            if r.status == ApprovalStatus.REJECTED and r.rejection_reason:
                reasons[r.rejection_reason] = reasons.get(r.rejection_reason, 0) + 1
        results = [{"reason": k, "count": v} for k, v in reasons.items()]
        results.sort(key=lambda x: x["count"], reverse=True)
        return results

    def get_tier_distribution(self) -> dict[str, int]:
        """Count requests per tier."""
        dist: dict[str, int] = {}
        for r in self._records:
            dist[r.required_tier.value] = dist.get(r.required_tier.value, 0) + 1
        return dist

    # -- helpers --------------------------------------------------------------

    def _find(self, approval_id: str) -> ApprovalRecord | None:
        for r in self._records:
            if r.id == approval_id:
                return r
        return None

    # -- report / stats -------------------------------------------------------

    def generate_approval_report(self) -> ApprovalReport:
        by_tier: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for r in self._records:
            by_tier[r.required_tier.value] = by_tier.get(r.required_tier.value, 0) + 1
            by_severity[r.severity] = by_severity.get(r.severity, 0) + 1
        auto = sum(1 for r in self._records if r.status == ApprovalStatus.AUTO_APPROVED)
        approved = sum(1 for r in self._records if r.status == ApprovalStatus.APPROVED)
        rejected = sum(1 for r in self._records if r.status == ApprovalStatus.REJECTED)
        expired = sum(1 for r in self._records if r.status == ApprovalStatus.EXPIRED)
        pending = sum(1 for r in self._records if r.status == ApprovalStatus.PENDING)
        latency = self.get_approval_latency_stats()
        recs: list[str] = []
        if expired > 0:
            recs.append(f"{expired} approval(s) expired — review escalation thresholds")
        if pending > 5:
            recs.append(f"{pending} approvals pending — possible bottleneck")
        rejection_rate = rejected / len(self._records) * 100 if self._records else 0.0
        if rejection_rate > 30:
            recs.append(f"High rejection rate ({rejection_rate:.1f}%) — tune confidence routing")
        if not recs:
            recs.append("Approval workflow operating within targets")
        return ApprovalReport(
            total_requests=len(self._records),
            auto_approved=auto,
            manually_approved=approved,
            rejected=rejected,
            expired=expired,
            pending=pending,
            avg_response_time_seconds=latency["avg_seconds"],
            by_tier=by_tier,
            by_severity=by_severity,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_requests": len(self._records),
            "pending": sum(1 for r in self._records if r.status == ApprovalStatus.PENDING),
            "auto_approved": sum(
                1 for r in self._records if r.status == ApprovalStatus.AUTO_APPROVED
            ),
            "tier_distribution": self.get_tier_distribution(),
            "policy": self._policy.model_dump(),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("response_approval_workflow.cleared")
        return {"status": "cleared"}
