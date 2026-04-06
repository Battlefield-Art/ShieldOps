"""NL Query suggestions — recommend queries based on recent events."""

from __future__ import annotations

from typing import Any

_DEFAULT_SUGGESTIONS: list[dict[str, str]] = [
    {
        "title": "Failed logins in last 24h",
        "question": "Show me all failed logins in the last 24 hours",
        "category": "authentication",
    },
    {
        "title": "Top source IPs this week",
        "question": "What are the top 10 source IPs by event volume this week?",
        "category": "network",
    },
    {
        "title": "Alert volume week-over-week",
        "question": "Compare alert volume this week vs last week",
        "category": "trend",
    },
    {
        "title": "GuardDuty findings by user",
        "question": "Which users triggered the most GuardDuty findings?",
        "category": "security",
    },
    {
        "title": "Daily threat briefing",
        "question": "Give me a daily threat briefing for the last 24 hours",
        "category": "executive",
    },
]


def suggest_queries(
    *, org_id: str, recent_event_types: list[str] | None = None, limit: int = 5
) -> list[dict[str, str]]:
    """Return context-aware query suggestions for an organization.

    Currently uses static templates; a future version can rank by the actual
    event types recently ingested for this org (passed in via
    ``recent_event_types``).
    """
    ranked = list(_DEFAULT_SUGGESTIONS)
    if recent_event_types:
        type_set = {t.lower() for t in recent_event_types}

        def _score(item: dict[str, Any]) -> int:
            return sum(1 for t in type_set if t in item["question"].lower())

        ranked.sort(key=_score, reverse=True)
    return ranked[:limit]
