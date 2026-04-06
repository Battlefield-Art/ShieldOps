"""Agent Firewall dashboard data endpoints.

Provides aggregated stats and a paginated evaluation stream for the
Agent Firewall Monitor dashboard.  Data is stored in-memory via
module-level counters populated by ``record_evaluation()`` — called from
the evaluation endpoint in ``firewall_policies.py``.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger()
router = APIRouter(prefix="/firewall/dashboard", tags=["Firewall Dashboard"])

# ---------------------------------------------------------------------------
# In-memory counters (org_id -> data)
# ---------------------------------------------------------------------------

_MAX_STREAM_ENTRIES = 500  # rolling buffer per org

# Per-org evaluation counters
_totals: dict[str, int] = defaultdict(int)
_blocked: dict[str, int] = defaultdict(int)
_allowed: dict[str, int] = defaultdict(int)
_review: dict[str, int] = defaultdict(int)

# Per-org tool-level stats: tool_name -> {count, total_risk}
_tool_stats: dict[str, dict[str, dict[str, float]]] = defaultdict(
    lambda: defaultdict(lambda: {"count": 0.0, "total_risk": 0.0})
)

# Per-org hourly buckets: hour_key -> count
_hourly: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

# Per-org recent evaluations (ring buffer)
_stream: dict[str, list[dict[str, Any]]] = defaultdict(list)


def _org_id_from_user(user: UserResponse) -> str:
    return getattr(user, "org_id", None) or user.id


# ---------------------------------------------------------------------------
# Public helper — called from firewall_policies.evaluate_tool_call
# ---------------------------------------------------------------------------


def record_evaluation(
    org_id: str,
    tool_name: str,
    decision: str,
    risk_score: float,
    caller: str = "",
) -> None:
    """Record an evaluation result into in-memory counters."""
    _totals[org_id] += 1

    if decision == "deny":
        _blocked[org_id] += 1
    elif decision == "review":
        _review[org_id] += 1
    else:
        _allowed[org_id] += 1

    # Tool stats
    ts = _tool_stats[org_id][tool_name]
    ts["count"] += 1
    ts["total_risk"] += risk_score

    # Hourly bucket
    hour_key = time.strftime("%Y-%m-%dT%H:00:00Z", time.gmtime())
    _hourly[org_id][hour_key] += 1

    # Stream entry
    entry: dict[str, Any] = {
        "tool_name": tool_name,
        "decision": decision,
        "risk_score": round(risk_score, 4),
        "caller": caller,
        "timestamp": time.time(),
    }
    buf = _stream[org_id]
    buf.append(entry)
    if len(buf) > _MAX_STREAM_ENTRIES:
        _stream[org_id] = buf[-_MAX_STREAM_ENTRIES:]


def reset_counters() -> None:
    """Reset all in-memory counters (useful for testing)."""
    _totals.clear()
    _blocked.clear()
    _allowed.clear()
    _review.clear()
    _tool_stats.clear()
    _hourly.clear()
    _stream.clear()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class ToolRiskSummary(BaseModel):
    tool_name: str
    count: int
    avg_risk: float


class DashboardStatsResponse(BaseModel):
    total_evaluations: int = 0
    blocked_count: int = 0
    allowed_count: int = 0
    review_count: int = 0
    top_risky_tools: list[ToolRiskSummary] = Field(default_factory=list)
    evaluations_per_hour: dict[str, int] = Field(default_factory=dict)


class StreamEntry(BaseModel):
    tool_name: str
    decision: str
    risk_score: float
    caller: str = ""
    timestamp: float = 0.0


class StreamResponse(BaseModel):
    evaluations: list[StreamEntry] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    limit: int = 50


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(
    user: UserResponse = Depends(get_current_user),
) -> DashboardStatsResponse:
    """Return aggregated firewall evaluation statistics for the caller's org."""
    org = _org_id_from_user(user)

    # Build top risky tools (sorted by avg_risk desc, top 10)
    tool_summaries: list[ToolRiskSummary] = []
    for tool_name, stats in _tool_stats.get(org, {}).items():
        count = int(stats["count"])
        avg_risk = round(stats["total_risk"] / count, 4) if count > 0 else 0.0
        tool_summaries.append(ToolRiskSummary(tool_name=tool_name, count=count, avg_risk=avg_risk))
    tool_summaries.sort(key=lambda t: t.avg_risk, reverse=True)

    return DashboardStatsResponse(
        total_evaluations=_totals.get(org, 0),
        blocked_count=_blocked.get(org, 0),
        allowed_count=_allowed.get(org, 0),
        review_count=_review.get(org, 0),
        top_risky_tools=tool_summaries[:10],
        evaluations_per_hour=dict(_hourly.get(org, {})),
    )


@router.get("/stream", response_model=StreamResponse)
async def get_evaluation_stream(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=100),
    user: UserResponse = Depends(get_current_user),
) -> StreamResponse:
    """Return the last evaluations (paginated, newest first)."""
    org = _org_id_from_user(user)
    buf = _stream.get(org, [])

    # Newest first
    reversed_buf = list(reversed(buf))
    total = len(reversed_buf)
    start = (page - 1) * limit
    end = start + limit
    page_items = reversed_buf[start:end]

    return StreamResponse(
        evaluations=[StreamEntry(**e) for e in page_items],
        total=total,
        page=page,
        limit=limit,
    )
