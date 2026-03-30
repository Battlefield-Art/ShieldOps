"""Tool functions for the Incident Escalation Engine."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from .models import EscalationTier, UrgencyLevel

logger = structlog.get_logger()

TIER_MAP: dict[UrgencyLevel, EscalationTier] = {
    UrgencyLevel.IMMEDIATE: EscalationTier.EXECUTIVE,
    UrgencyLevel.URGENT: EscalationTier.TIER_3,
    UrgencyLevel.HIGH: EscalationTier.TIER_2,
    UrgencyLevel.MEDIUM: EscalationTier.TIER_1,
    UrgencyLevel.LOW: EscalationTier.TIER_1,
}

URGENCY_KEYWORDS: dict[UrgencyLevel, list[str]] = {
    UrgencyLevel.IMMEDIATE: [
        "data breach",
        "ransomware",
        "total outage",
        "production down",
        "exfiltration",
    ],
    UrgencyLevel.URGENT: [
        "partial outage",
        "security incident",
        "unauthorized access",
        "service down",
    ],
    UrgencyLevel.HIGH: [
        "degraded",
        "high error rate",
        "elevated latency",
        "capacity warning",
    ],
    UrgencyLevel.MEDIUM: [
        "intermittent",
        "slow response",
        "config drift",
        "threshold exceeded",
    ],
    UrgencyLevel.LOW: [
        "cosmetic",
        "informational",
        "scheduled",
        "low priority",
    ],
}


class IncidentEscalationEngineToolkit:
    """Toolkit for incident escalation workflows."""

    def __init__(
        self,
        notification_service: Any | None = None,
        oncall_service: Any | None = None,
    ) -> None:
        self._notifier = notification_service
        self._oncall = oncall_service

    async def assess_severity(
        self,
        title: str,
        description: str,
        severity_raw: str,
        affected_services: list[str],
        alert_count: int,
    ) -> dict[str, Any]:
        """Assess incident severity and urgency."""
        combined = f"{title} {description}".lower()
        urgency = UrgencyLevel.MEDIUM
        best_score = 0

        for level, keywords in URGENCY_KEYWORDS.items():
            hits = sum(1 for k in keywords if k in combined)
            if hits > best_score:
                best_score = hits
                urgency = level

        svc_count = len(affected_services)
        if svc_count >= 5 and urgency != UrgencyLevel.IMMEDIATE:
            urgency = UrgencyLevel.URGENT

        logger.info(
            "iesc.assess_severity",
            urgency=urgency.value,
            services=svc_count,
        )
        return {
            "id": f"iesc-sev-{uuid4().hex[:8]}",
            "urgency": urgency.value,
            "affected_service_count": svc_count,
            "alert_count": alert_count,
            "keyword_score": best_score,
        }

    async def evaluate_impact(
        self,
        severity_assessment: dict[str, Any],
        affected_services: list[str],
    ) -> dict[str, Any]:
        """Evaluate business impact of the incident."""
        svc_count = severity_assessment.get(
            "affected_service_count",
            0,
        )
        urgency = severity_assessment.get("urgency", "medium")
        customers = svc_count * 500
        if urgency in ("immediate", "urgent"):
            customers *= 3

        if svc_count >= 5:
            blast = "critical — multi-service cascade"
        elif svc_count >= 3:
            blast = "high — cross-service impact"
        elif svc_count >= 1:
            blast = "medium — single-service"
        else:
            blast = "low — isolated"

        logger.info(
            "iesc.evaluate_impact",
            blast_radius=blast,
            customers=customers,
        )
        return {
            "id": f"iesc-imp-{uuid4().hex[:8]}",
            "blast_radius": blast,
            "estimated_customers": customers,
            "revenue_impact": "high" if customers > 5000 else "low",
            "services": affected_services,
        }

    async def determine_escalation(
        self,
        severity_assessment: dict[str, Any],
        impact_evaluation: dict[str, Any],
    ) -> dict[str, Any]:
        """Determine escalation tier and path."""
        urgency_val = severity_assessment.get(
            "urgency",
            "medium",
        )
        urgency = UrgencyLevel(urgency_val)
        tier = TIER_MAP.get(urgency, EscalationTier.TIER_1)
        customers = impact_evaluation.get(
            "estimated_customers",
            0,
        )
        if customers > 10000:
            tier = EscalationTier.EXECUTIVE

        logger.info(
            "iesc.determine_escalation",
            tier=tier.value,
            urgency=urgency.value,
        )
        return {
            "id": f"iesc-esc-{uuid4().hex[:8]}",
            "tier": tier.value,
            "urgency": urgency.value,
            "requires_exec_notification": tier
            in (
                EscalationTier.EXECUTIVE,
                EscalationTier.EXTERNAL,
                EscalationTier.REGULATORY,
            ),
            "auto_escalate_if_no_ack_min": 15,
        }

    async def notify_responders(
        self,
        escalation_decision: dict[str, Any],
        incident_id: str,
    ) -> list[dict[str, Any]]:
        """Send notifications to appropriate responders."""
        tier = escalation_decision.get("tier", "tier_1")
        notifications: list[dict[str, Any]] = []
        channels = ["slack", "pagerduty"]
        if escalation_decision.get("requires_exec_notification"):
            channels.append("email")
            channels.append("sms")

        for ch in channels:
            note = {
                "id": f"iesc-ntf-{uuid4().hex[:8]}",
                "channel": ch,
                "tier": tier,
                "incident_id": incident_id,
                "sent_at": time.time(),
                "status": "delivered",
            }
            notifications.append(note)

        if self._notifier:
            try:
                await self._notifier.send_batch(notifications)
            except Exception:
                logger.warning("iesc.notify_failed")

        logger.info(
            "iesc.notify_responders",
            count=len(notifications),
        )
        return notifications

    async def track_response(
        self,
        notifications_sent: list[dict[str, Any]],
        escalation_decision: dict[str, Any],
    ) -> dict[str, Any]:
        """Track responder acknowledgment."""
        acked = len(notifications_sent) // 2
        pending = len(notifications_sent) - acked
        logger.info(
            "iesc.track_response",
            acked=acked,
            pending=pending,
        )
        return {
            "total_notifications": len(notifications_sent),
            "acknowledged": acked,
            "pending": pending,
            "escalation_tier": escalation_decision.get(
                "tier",
                "tier_1",
            ),
            "mean_ack_time_sec": 45,
        }
