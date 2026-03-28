"""Tool functions for the Post-Incident Analyzer Agent."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.post_incident_analyzer.models import (
    ActionItem,
    ImpactLevel,
    RootCauseCategory,
)

logger = structlog.get_logger()

# Keyword patterns for heuristic root-cause classification
ROOT_CAUSE_KEYWORDS: dict[RootCauseCategory, list[str]] = {
    RootCauseCategory.HUMAN_ERROR: [
        "manual change",
        "misconfigured by",
        "typo",
        "wrong command",
        "skipped step",
        "forgot",
        "overlooked",
        "accidental",
    ],
    RootCauseCategory.SOFTWARE_BUG: [
        "bug",
        "null pointer",
        "exception",
        "regression",
        "race condition",
        "memory leak",
        "crash",
        "stack overflow",
    ],
    RootCauseCategory.CONFIGURATION: [
        "config",
        "misconfiguration",
        "wrong setting",
        "environment variable",
        "feature flag",
        "threshold",
        "parameter",
        "yaml error",
    ],
    RootCauseCategory.INFRASTRUCTURE: [
        "hardware",
        "disk full",
        "network partition",
        "dns failure",
        "certificate expired",
        "capacity",
        "node failure",
        "az outage",
    ],
    RootCauseCategory.EXTERNAL_ATTACK: [
        "ddos",
        "brute force",
        "exploit",
        "vulnerability",
        "malware",
        "unauthorized access",
        "injection",
        "phishing",
    ],
    RootCauseCategory.PROCESS_GAP: [
        "no runbook",
        "missing alert",
        "no review",
        "untested",
        "no rollback",
        "missing monitoring",
        "no approval",
        "undocumented",
    ],
}

# Impact thresholds by affected-service count and duration
IMPACT_THRESHOLDS: list[tuple[ImpactLevel, int, int]] = [
    (ImpactLevel.CRITICAL, 5, 60),
    (ImpactLevel.HIGH, 3, 30),
    (ImpactLevel.MEDIUM, 1, 10),
    (ImpactLevel.LOW, 1, 0),
]


class PostIncidentAnalyzerToolkit:
    """Toolkit for post-incident analysis — timeline, root cause,
    impact, lessons, and action items."""

    def __init__(
        self,
        incident_db: Any | None = None,
        alert_service: Any | None = None,
        change_db: Any | None = None,
    ) -> None:
        self._incident_db = incident_db
        self._alert_service = alert_service
        self._change_db = change_db

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _match_keywords(
        self,
        text: str,
        keyword_map: dict[Any, list[str]],
    ) -> tuple[Any, float]:
        """Match *text* against keyword patterns and return the best
        matching key together with a normalised confidence score."""
        text_lower = text.lower()
        best_key = None
        best_score = 0.0

        for key, keywords in keyword_map.items():
            hits = sum(1 for kw in keywords if kw in text_lower)
            if hits > best_score:
                best_score = hits
                best_key = key

        if best_key is not None:
            max_possible = len(keyword_map[best_key])
            best_score = best_score / max_possible if max_possible > 0 else 0.0

        return best_key, best_score

    # ------------------------------------------------------------------
    # Tool methods
    # ------------------------------------------------------------------

    async def gather_timeline(
        self,
        incident_id: str,
    ) -> list[dict[str, Any]]:
        """Gather chronological timeline events for *incident_id*.

        Pulls alerts, changes, and actions into a unified timeline
        ordered by timestamp.
        """
        events: list[dict[str, Any]] = []

        # Alerts ---------------------------------------------------------
        if self._alert_service is not None:
            try:
                raw_alerts = await self._alert_service.get_alerts(incident_id)
                for alert in raw_alerts:
                    events.append(
                        {
                            "timestamp": alert.get("timestamp", ""),
                            "type": "alert",
                            "source": alert.get("source", "unknown"),
                            "description": alert.get("description", ""),
                            "severity": alert.get("severity", "info"),
                        }
                    )
            except Exception:
                logger.debug(
                    "alert_fetch_failed",
                    incident_id=incident_id,
                )

        # Recent changes -------------------------------------------------
        if self._change_db is not None:
            try:
                changes = await self._change_db.recent_changes(
                    incident_id=incident_id, window_hours=24
                )
                for change in changes:
                    events.append(
                        {
                            "timestamp": change.get("timestamp", ""),
                            "type": "change",
                            "source": change.get("author", "unknown"),
                            "description": change.get("description", ""),
                            "severity": "info",
                        }
                    )
            except Exception:
                logger.debug(
                    "change_fetch_failed",
                    incident_id=incident_id,
                )

        # Incident history -----------------------------------------------
        if self._incident_db is not None:
            try:
                history = await self._incident_db.get_history(incident_id)
                for entry in history:
                    events.append(
                        {
                            "timestamp": entry.get("timestamp", ""),
                            "type": "action",
                            "source": entry.get("actor", "system"),
                            "description": entry.get("description", ""),
                            "severity": entry.get("severity", "info"),
                        }
                    )
            except Exception:
                logger.debug(
                    "history_fetch_failed",
                    incident_id=incident_id,
                )

        # Fallback baseline when no external sources are available
        if not events:
            now = time.time()
            events = [
                {
                    "timestamp": now - 3600,
                    "type": "alert",
                    "source": "monitoring",
                    "description": (f"Initial alert for {incident_id}"),
                    "severity": "warning",
                },
                {
                    "timestamp": now - 3000,
                    "type": "action",
                    "source": "on-call",
                    "description": "Incident acknowledged",
                    "severity": "info",
                },
                {
                    "timestamp": now - 1800,
                    "type": "action",
                    "source": "engineering",
                    "description": "Investigation started",
                    "severity": "info",
                },
                {
                    "timestamp": now - 600,
                    "type": "action",
                    "source": "engineering",
                    "description": "Fix applied",
                    "severity": "info",
                },
                {
                    "timestamp": now,
                    "type": "action",
                    "source": "engineering",
                    "description": "Incident resolved",
                    "severity": "info",
                },
            ]

        events.sort(key=lambda e: e.get("timestamp", 0))

        logger.info(
            "post_incident.timeline_gathered",
            incident_id=incident_id,
            event_count=len(events),
        )
        return events

    async def analyze_root_cause(
        self,
        timeline_events: list[dict[str, Any]],
    ) -> tuple[RootCauseCategory, str]:
        """Determine root-cause category and reasoning from timeline
        events."""
        combined = " ".join(e.get("description", "") for e in timeline_events)

        match, score = self._match_keywords(combined, ROOT_CAUSE_KEYWORDS)
        category: RootCauseCategory = match or RootCauseCategory.SOFTWARE_BUG

        alerts = [e for e in timeline_events if e.get("type") == "alert"]
        changes = [e for e in timeline_events if e.get("type") == "change"]

        parts: list[str] = [
            f"Keyword analysis -> {category.value} (score={score:.2f})",
        ]
        if changes:
            parts.append(f"{len(changes)} change(s) may have contributed")
        if alerts:
            parts.append(f"Analysed {len(alerts)} alert(s)")

        reasoning = "; ".join(parts)

        logger.info(
            "post_incident.root_cause_analyzed",
            category=category.value,
            confidence=score,
        )
        return category, reasoning

    async def assess_impact(
        self,
        incident_id: str,
        root_cause: RootCauseCategory,
    ) -> ImpactLevel:
        """Assess impact level for *incident_id*."""
        affected_services = 0
        duration_min = 0

        if self._incident_db is not None:
            try:
                details = await self._incident_db.get_details(incident_id)
                affected_services = details.get("affected_services", 0)
                duration_min = details.get("duration_minutes", 0)
            except Exception:
                logger.debug(
                    "impact_detail_fetch_failed",
                    incident_id=incident_id,
                )

        # External attacks / infra failures bias toward higher impact
        if root_cause in (
            RootCauseCategory.EXTERNAL_ATTACK,
            RootCauseCategory.INFRASTRUCTURE,
        ):
            affected_services = max(affected_services, 3)

        for level, min_svc, min_dur in IMPACT_THRESHOLDS:
            if affected_services >= min_svc and duration_min >= min_dur:
                logger.info(
                    "post_incident.impact_assessed",
                    incident_id=incident_id,
                    impact=level.value,
                )
                return level

        logger.info(
            "post_incident.impact_assessed",
            incident_id=incident_id,
            impact=ImpactLevel.NEGLIGIBLE.value,
        )
        return ImpactLevel.NEGLIGIBLE

    async def extract_lessons(
        self,
        timeline: list[dict[str, Any]],
        root_cause: RootCauseCategory,
    ) -> list[dict[str, str]]:
        """Extract lessons learned from *timeline* and *root_cause*."""
        lessons: list[dict[str, str]] = []

        # Detection-speed lesson
        first_alert = next(
            (e for e in timeline if e.get("type") == "alert"),
            None,
        )
        first_action = next(
            (e for e in timeline if e.get("type") == "action"),
            None,
        )
        if first_alert and first_action:
            t_a = first_alert.get("timestamp", 0)
            t_b = first_action.get("timestamp", 0)
            if isinstance(t_a, int | float) and isinstance(t_b, int | float):
                delay = (t_b - t_a) / 60
                if delay > 15:
                    lessons.append(
                        {
                            "area": "detection",
                            "lesson": (f"Response delay {delay:.0f}min after first alert"),
                            "priority": "high",
                        }
                    )
                else:
                    lessons.append(
                        {
                            "area": "detection",
                            "lesson": (f"Response within {delay:.0f}min"),
                            "priority": "low",
                        }
                    )

        # Root-cause-specific lessons
        _cause_lessons: dict[RootCauseCategory, dict[str, str]] = {
            RootCauseCategory.HUMAN_ERROR: {
                "area": "process",
                "lesson": ("Add pre-change checklists and peer review"),
                "priority": "high",
            },
            RootCauseCategory.SOFTWARE_BUG: {
                "area": "engineering",
                "lesson": ("Improve test coverage for affected path"),
                "priority": "high",
            },
            RootCauseCategory.CONFIGURATION: {
                "area": "operations",
                "lesson": ("Add config validation and drift detection"),
                "priority": "medium",
            },
            RootCauseCategory.INFRASTRUCTURE: {
                "area": "reliability",
                "lesson": ("Review redundancy and failover mechanisms"),
                "priority": "high",
            },
            RootCauseCategory.EXTERNAL_ATTACK: {
                "area": "security",
                "lesson": ("Strengthen defenses for this attack vector"),
                "priority": "critical",
            },
            RootCauseCategory.PROCESS_GAP: {
                "area": "process",
                "lesson": ("Document and test runbooks with rollback"),
                "priority": "high",
            },
        }
        if root_cause in _cause_lessons:
            lessons.append(_cause_lessons[root_cause])

        lessons.append(
            {
                "area": "observability",
                "lesson": ("Review monitoring coverage for similar issues"),
                "priority": "medium",
            }
        )

        logger.info(
            "post_incident.lessons_extracted",
            count=len(lessons),
        )
        return lessons

    async def generate_action_items(
        self,
        lessons: list[dict[str, str]],
    ) -> list[ActionItem]:
        """Turn lessons into concrete action items."""
        owner_map: dict[str, str] = {
            "detection": "sre-team",
            "process": "engineering-leads",
            "engineering": "dev-team",
            "operations": "platform-team",
            "reliability": "sre-team",
            "security": "security-team",
            "observability": "platform-team",
        }

        items: list[ActionItem] = []
        for lesson in lessons:
            area = lesson.get("area", "general")
            items.append(
                ActionItem(
                    id=f"act-{uuid4().hex[:8]}",
                    title=lesson.get("lesson", ""),
                    owner=owner_map.get(area, "engineering-leads"),
                    priority=lesson.get("priority", "medium"),
                    due_date="",
                    completed=False,
                )
            )

        logger.info(
            "post_incident.action_items_generated",
            count=len(items),
        )
        return items
