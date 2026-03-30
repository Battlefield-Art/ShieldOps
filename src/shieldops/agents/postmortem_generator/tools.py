"""Tool functions for the Postmortem Generator."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from .models import ActionPriority, IncidentCategory

logger = structlog.get_logger()

CATEGORY_KEYWORDS: dict[IncidentCategory, list[str]] = {
    IncidentCategory.AVAILABILITY: [
        "outage",
        "down",
        "unavailable",
        "timeout",
    ],
    IncidentCategory.SECURITY: [
        "breach",
        "unauthorized",
        "malware",
        "vuln",
    ],
    IncidentCategory.PERFORMANCE: [
        "latency",
        "slow",
        "degraded",
        "cpu",
    ],
    IncidentCategory.DATA_INTEGRITY: [
        "data loss",
        "corruption",
        "inconsistent",
    ],
    IncidentCategory.COMPLIANCE: [
        "compliance",
        "audit",
        "regulatory",
        "gdpr",
    ],
    IncidentCategory.CONFIGURATION: [
        "config",
        "misconfiguration",
        "drift",
    ],
}


class PostmortemGeneratorToolkit:
    """Toolkit for postmortem generation workflows."""

    def __init__(
        self,
        incident_store: Any | None = None,
        change_store: Any | None = None,
    ) -> None:
        self._incidents = incident_store
        self._changes = change_store

    async def collect_timeline(
        self,
        incident_id: str,
        incident_description: str,
        resolution_summary: str,
    ) -> list[dict[str, Any]]:
        """Collect incident timeline events."""
        now = time.time()
        events: list[dict[str, Any]] = [
            {
                "id": f"pmg-evt-{uuid4().hex[:8]}",
                "timestamp": now - 7200,
                "event": "First alert triggered",
                "source": "monitoring",
            },
            {
                "id": f"pmg-evt-{uuid4().hex[:8]}",
                "timestamp": now - 6600,
                "event": "Incident acknowledged",
                "source": "pagerduty",
            },
            {
                "id": f"pmg-evt-{uuid4().hex[:8]}",
                "timestamp": now - 5400,
                "event": "Root cause identified",
                "source": "investigation",
            },
            {
                "id": f"pmg-evt-{uuid4().hex[:8]}",
                "timestamp": now - 3600,
                "event": "Fix deployed",
                "source": "deployment",
            },
            {
                "id": f"pmg-evt-{uuid4().hex[:8]}",
                "timestamp": now - 1800,
                "event": "Service recovered",
                "source": "monitoring",
            },
        ]

        if self._incidents:
            try:
                stored = await self._incidents.get_timeline(
                    incident_id,
                )
                if stored:
                    events = stored
            except Exception:
                logger.debug("pmg.timeline_fallback")

        logger.info(
            "pmg.collect_timeline",
            events=len(events),
        )
        return events

    async def analyze_root_cause(
        self,
        timeline_events: list[dict[str, Any]],
        incident_description: str,
        affected_services: list[str],
    ) -> dict[str, Any]:
        """Analyze root cause from timeline."""
        desc_lower = incident_description.lower()
        category = IncidentCategory.CONFIGURATION
        for cat, keywords in CATEGORY_KEYWORDS.items():
            if any(k in desc_lower for k in keywords):
                category = cat
                break

        logger.info(
            "pmg.analyze_root_cause",
            category=category.value,
        )
        return {
            "id": f"pmg-rca-{uuid4().hex[:8]}",
            "category": category.value,
            "root_cause": ("System change without adequate testing"),
            "contributing_factors": [
                "Missing integration tests",
                "No canary deployment",
                "Insufficient monitoring",
            ],
            "timeline_events_analyzed": len(
                timeline_events,
            ),
            "affected_service_count": len(
                affected_services,
            ),
            "detection_time_min": 10,
            "resolution_time_min": 90,
        }

    async def identify_actions(
        self,
        root_cause_analysis: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Identify action items from root cause."""
        actions: list[dict[str, Any]] = [
            {
                "id": f"pmg-act-{uuid4().hex[:8]}",
                "title": "Add integration tests",
                "priority": ActionPriority.P1_WEEK.value,
                "owner": "engineering",
                "status": "open",
            },
            {
                "id": f"pmg-act-{uuid4().hex[:8]}",
                "title": "Implement canary deployments",
                "priority": ActionPriority.P2_SPRINT.value,
                "owner": "platform",
                "status": "open",
            },
            {
                "id": f"pmg-act-{uuid4().hex[:8]}",
                "title": "Improve monitoring coverage",
                "priority": ActionPriority.P1_WEEK.value,
                "owner": "sre",
                "status": "open",
            },
            {
                "id": f"pmg-act-{uuid4().hex[:8]}",
                "title": "Update runbook",
                "priority": ActionPriority.P0_IMMEDIATE.value,
                "owner": "on-call",
                "status": "open",
            },
        ]

        logger.info(
            "pmg.identify_actions",
            count=len(actions),
        )
        return actions

    async def draft_document(
        self,
        incident_title: str,
        timeline_events: list[dict[str, Any]],
        root_cause_analysis: dict[str, Any],
        action_items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Draft the postmortem document."""
        logger.info("pmg.draft_document")
        return {
            "id": f"pmg-doc-{uuid4().hex[:8]}",
            "title": f"Postmortem: {incident_title}",
            "sections": [
                "Summary",
                "Timeline",
                "Root Cause",
                "Impact",
                "Action Items",
                "Lessons Learned",
            ],
            "timeline_count": len(timeline_events),
            "action_count": len(action_items),
            "root_cause": root_cause_analysis.get(
                "root_cause",
                "",
            ),
            "category": root_cause_analysis.get(
                "category",
                "",
            ),
            "drafted_at": time.time(),
        }

    async def review_quality(
        self,
        document_draft: dict[str, Any],
        action_items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Review postmortem document quality."""
        has_timeline = (
            document_draft.get(
                "timeline_count",
                0,
            )
            > 0
        )
        has_rca = bool(
            document_draft.get("root_cause"),
        )
        has_actions = len(action_items) > 0
        has_p0 = any(a.get("priority") == "p0_immediate" for a in action_items)

        score = sum(
            [
                has_timeline,
                has_rca,
                has_actions,
                has_p0,
            ]
        )
        if score >= 4:
            quality = "thorough"
        elif score >= 2:
            quality = "adequate"
        else:
            quality = "needs_work"

        logger.info(
            "pmg.review_quality",
            quality=quality,
        )
        return {
            "id": f"pmg-rev-{uuid4().hex[:8]}",
            "quality": quality,
            "score": score,
            "has_timeline": has_timeline,
            "has_root_cause": has_rca,
            "has_actions": has_actions,
            "has_immediate_actions": has_p0,
        }
