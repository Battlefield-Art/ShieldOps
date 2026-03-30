"""Tool functions for the Stakeholder Notifier."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from .models import (
    NotificationPriority,
    StakeholderGroup,
)

logger = structlog.get_logger()

SEVERITY_PRIORITY: dict[str, NotificationPriority] = {
    "critical": NotificationPriority.CRITICAL,
    "sev1": NotificationPriority.CRITICAL,
    "sev2": NotificationPriority.HIGH,
    "high": NotificationPriority.HIGH,
    "medium": NotificationPriority.MEDIUM,
    "low": NotificationPriority.LOW,
    "info": NotificationPriority.INFORMATIONAL,
}

GROUP_CHANNELS: dict[StakeholderGroup, list[str]] = {
    StakeholderGroup.ENGINEERING: ["slack", "pagerduty"],
    StakeholderGroup.MANAGEMENT: ["email", "slack"],
    StakeholderGroup.CUSTOMERS: [
        "email",
        "status_page",
    ],
    StakeholderGroup.PARTNERS: ["email"],
    StakeholderGroup.REGULATORS: [
        "email",
        "formal_letter",
    ],
    StakeholderGroup.MEDIA: ["email", "press_release"],
}


class StakeholderNotifierToolkit:
    """Toolkit for stakeholder notification workflows."""

    def __init__(
        self,
        notification_service: Any | None = None,
        contact_directory: Any | None = None,
    ) -> None:
        self._notifier = notification_service
        self._contacts = contact_directory

    async def identify_stakeholders(
        self,
        incident_severity: str,
        affected_services: list[str],
        incident_description: str,
    ) -> list[dict[str, Any]]:
        """Identify stakeholders to notify."""
        sev = incident_severity.lower()
        priority = SEVERITY_PRIORITY.get(
            sev,
            NotificationPriority.MEDIUM,
        )

        groups: list[StakeholderGroup] = [
            StakeholderGroup.ENGINEERING,
        ]
        if priority in (
            NotificationPriority.CRITICAL,
            NotificationPriority.HIGH,
        ):
            groups.append(StakeholderGroup.MANAGEMENT)
        if priority == NotificationPriority.CRITICAL:
            groups.append(StakeholderGroup.CUSTOMERS)

        desc_lower = incident_description.lower()
        if any(w in desc_lower for w in ["breach", "gdpr", "hipaa", "pci"]):
            groups.append(StakeholderGroup.REGULATORS)
        if "partner" in desc_lower:
            groups.append(StakeholderGroup.PARTNERS)

        stakeholders: list[dict[str, Any]] = []
        for grp in groups:
            stakeholders.append(
                {
                    "id": f"sn-stk-{uuid4().hex[:8]}",
                    "group": grp.value,
                    "priority": priority.value,
                    "contact_count": 5,
                }
            )

        logger.info(
            "sn.identify_stakeholders",
            groups=len(stakeholders),
        )
        return stakeholders

    async def assess_impact(
        self,
        stakeholders: list[dict[str, Any]],
        affected_services: list[str],
    ) -> dict[str, Any]:
        """Assess communication impact scope."""
        total_contacts = sum(s.get("contact_count", 0) for s in stakeholders)
        logger.info(
            "sn.assess_impact",
            contacts=total_contacts,
        )
        return {
            "id": f"sn-imp-{uuid4().hex[:8]}",
            "total_stakeholder_groups": len(stakeholders),
            "total_contacts": total_contacts,
            "affected_service_count": len(
                affected_services,
            ),
            "requires_public_comms": any(
                s.get("group")
                in (
                    "customers",
                    "media",
                    "regulators",
                )
                for s in stakeholders
            ),
        }

    async def compose_message(
        self,
        stakeholders: list[dict[str, Any]],
        incident_title: str,
        incident_description: str,
    ) -> list[dict[str, Any]]:
        """Compose targeted messages per group."""
        messages: list[dict[str, Any]] = []
        for stk in stakeholders:
            grp = stk.get("group", "engineering")
            if grp == "management":
                tone = "executive_brief"
            elif grp == "customers":
                tone = "customer_facing"
            elif grp == "regulators":
                tone = "formal_regulatory"
            else:
                tone = "technical"

            messages.append(
                {
                    "id": f"sn-msg-{uuid4().hex[:8]}",
                    "group": grp,
                    "tone": tone,
                    "subject": f"[{stk.get('priority', 'medium').upper()}] {incident_title}",
                    "body_preview": incident_description[:200],
                    "composed_at": time.time(),
                }
            )

        logger.info(
            "sn.compose_message",
            count=len(messages),
        )
        return messages

    async def select_channels(
        self,
        stakeholders: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Select delivery channels per group."""
        channels: list[dict[str, Any]] = []
        for stk in stakeholders:
            grp_val = stk.get("group", "engineering")
            try:
                grp = StakeholderGroup(grp_val)
            except ValueError:
                grp = StakeholderGroup.ENGINEERING

            ch_list = GROUP_CHANNELS.get(grp, ["email"])
            channels.append(
                {
                    "id": f"sn-ch-{uuid4().hex[:8]}",
                    "group": grp_val,
                    "channels": ch_list,
                }
            )

        logger.info(
            "sn.select_channels",
            count=len(channels),
        )
        return channels

    async def deliver_notification(
        self,
        composed_messages: list[dict[str, Any]],
        selected_channels: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Deliver notifications via selected channels."""
        results: list[dict[str, Any]] = []
        for msg in composed_messages:
            ch_match = next(
                (c for c in selected_channels if c.get("group") == msg.get("group")),
                {"channels": ["email"]},
            )
            for ch in ch_match.get("channels", []):
                results.append(
                    {
                        "id": f"sn-dlv-{uuid4().hex[:8]}",
                        "message_id": msg.get("id"),
                        "group": msg.get("group"),
                        "channel": ch,
                        "status": "delivered",
                        "delivered_at": time.time(),
                    }
                )

        if self._notifier:
            try:
                await self._notifier.send_batch(results)
            except Exception:
                logger.warning("sn.deliver_failed")

        logger.info(
            "sn.deliver_notification",
            count=len(results),
        )
        return results
