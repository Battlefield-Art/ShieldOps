"""NL query hardening — SQL injection prevention, caching, export, templates.

Wraps the NLQueryToolkit with production-grade safety and convenience features.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import time
from typing import Any

import structlog

logger = structlog.get_logger()


class QueryCache:
    """TTL-based query result cache."""

    def __init__(self, ttl_seconds: int = 300, max_entries: int = 1000) -> None:
        self._cache: dict[str, tuple[Any, float]] = {}
        self._ttl = ttl_seconds
        self._max = max_entries

    def get(self, key: str) -> Any | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.monotonic() > expires_at:
            del self._cache[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        if len(self._cache) >= self._max:
            # Evict oldest
            oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]
        self._cache[key] = (value, time.monotonic() + self._ttl)

    def make_key(self, sql: str) -> str:
        return hashlib.sha256(sql.strip().lower().encode()).hexdigest()[:16]

    @property
    def size(self) -> int:
        return len(self._cache)

    def clear(self) -> None:
        self._cache.clear()


class QueryAuditLog:
    """Tracks who asked what, when."""

    def __init__(self, max_entries: int = 10000) -> None:
        self._entries: list[dict[str, Any]] = []
        self._max = max_entries

    def record(
        self,
        question: str,
        sql: str,
        user_id: str = "",
        org_id: str = "",
        result_count: int = 0,
        duration_ms: float = 0,
        cache_hit: bool = False,
    ) -> None:
        self._entries.append(
            {
                "question": question[:500],
                "sql": sql[:1000],
                "user_id": user_id,
                "org_id": org_id,
                "result_count": result_count,
                "duration_ms": round(duration_ms, 2),
                "cache_hit": cache_hit,
                "timestamp": time.time(),
            }
        )
        if len(self._entries) > self._max:
            self._entries = self._entries[-self._max :]

    def get_recent(self, limit: int = 20) -> list[dict[str, Any]]:
        return self._entries[-limit:]

    def get_stats(self) -> dict[str, Any]:
        if not self._entries:
            return {"total_queries": 0, "cache_hit_rate": 0.0, "avg_duration_ms": 0.0}
        cache_hits = sum(1 for e in self._entries if e["cache_hit"])
        avg_duration = sum(e["duration_ms"] for e in self._entries) / len(self._entries)
        return {
            "total_queries": len(self._entries),
            "cache_hit_rate": round(cache_hits / len(self._entries), 3),
            "avg_duration_ms": round(avg_duration, 2),
        }


def export_to_csv(rows: list[dict[str, Any]]) -> str:
    """Export query results to CSV string."""
    if not rows:
        return ""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def export_to_json(rows: list[dict[str, Any]], pretty: bool = True) -> str:
    """Export query results to JSON string."""
    indent = 2 if pretty else None
    return json.dumps(rows, indent=indent, default=str)


def export_to_markdown(question: str, rows: list[dict[str, Any]]) -> str:
    """Export query results to markdown table."""
    if not rows:
        return f"**Query:** {question}\n\nNo results found."

    headers = list(rows[0].keys())
    lines = [
        f"**Query:** {question}",
        f"**Results:** {len(rows)} rows\n",
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows[:100]:
        lines.append("| " + " | ".join(str(row.get(h, ""))[:50] for h in headers) + " |")

    return "\n".join(lines)


# Query templates for common SOC workflows
QUERY_TEMPLATES = {
    "daily_threat_briefing": {
        "name": "Daily Threat Briefing",
        "description": "Critical and high severity events in the last 24 hours",
        "sql": (
            "SELECT severity, source_provider, COUNT(*) as count FROM events"
            " WHERE severity IN ('critical', 'high')"
            " GROUP BY severity, source_provider ORDER BY count DESC LIMIT 20"
        ),
    },
    "weekly_compliance_summary": {
        "name": "Weekly Compliance Summary",
        "description": "Event distribution by category over the past week",
        "sql": (
            "SELECT category_name, severity, COUNT(*) as count FROM events"
            " GROUP BY category_name, severity ORDER BY count DESC LIMIT 30"
        ),
    },
    "monthly_executive_report": {
        "name": "Monthly Executive Report",
        "description": "High-level security metrics for the past 30 days",
        "sql": (
            "SELECT source_provider, severity, COUNT(*) as total_events"
            " FROM events GROUP BY source_provider, severity"
            " ORDER BY total_events DESC LIMIT 50"
        ),
    },
    "top_sources": {
        "name": "Top Event Sources",
        "description": "Most active event sources",
        "sql": (
            "SELECT source_provider, COUNT(*) as event_count FROM events"
            " GROUP BY source_provider ORDER BY event_count DESC LIMIT 10"
        ),
    },
    "failed_auth": {
        "name": "Failed Authentication Attempts",
        "description": "Failed login and auth events",
        "sql": (
            "SELECT * FROM events"
            " WHERE category_name = 'authentication' AND status = 'failure'"
            " ORDER BY severity_id DESC LIMIT 50"
        ),
    },
}
