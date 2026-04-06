"""Business Value dashboard API — MTTD, MTTR, Cost/ROI, Data Volume, Risk.

Exposes executive-level business metrics aggregated from agent run data,
ingestion volumes, and incident timestamps. The repository layer currently
powers agent-run aggregation; ingestion volume, risk, and incident-derived
metrics are produced via deterministic placeholder computations until the
upstream pipelines are wired (see GitHub issue #207).

Endpoints:
- ``GET /api/v1/metrics/business``         → snapshot of 6 business KPIs
- ``GET /api/v1/metrics/business/trends``  → time-series for a single metric

Org isolation is enforced via the standard ``get_current_user`` dependency
(same pattern as ``agent_metrics_api.py``).
"""

from __future__ import annotations

from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse
from shieldops.db.repositories.agent_run import AgentRunRepository

logger = structlog.get_logger()

router = APIRouter(prefix="/metrics/business", tags=["Business Metrics"])

_run_repo: AgentRunRepository | None = None

# Ranges for business dashboards — executives rarely care about sub-day windows.
BusinessRange = Literal["24h", "7d", "30d"]
BusinessMetric = Literal["mttd", "mttr", "cost", "risk", "data_volume", "agent_roi"]


def set_run_repository(repo: AgentRunRepository) -> None:
    """Inject the AgentRunRepository (called during app startup)."""
    global _run_repo
    _run_repo = repo


def _get_run_repo() -> AgentRunRepository:
    if _run_repo is None:
        raise HTTPException(status_code=503, detail="Agent run repository not initialized")
    return _run_repo


def _extract_org_id(user: UserResponse) -> str:
    """Extract org_id from the authenticated user."""
    return getattr(user, "org_id", None) or user.id


# ── Response models ───────────────────────────────────────────────────


class BusinessMetricsResponse(BaseModel):
    """Executive-level business KPIs for the requested range."""

    range: str
    mttd_seconds: float = Field(ge=0.0, description="Mean time to detect")
    mttr_seconds: float = Field(ge=0.0, description="Mean time to remediate")
    cost_per_incident_usd: float = Field(ge=0.0)
    risk_score: float = Field(ge=0.0, le=100.0, description="Composite risk 0-100")
    data_volume_gb: float = Field(ge=0.0, description="Ingested telemetry volume")
    agent_roi_percent: float = Field(ge=0.0, description="Auto-resolved / total incidents × 100")
    incidents_total: int = Field(ge=0)
    incidents_auto_resolved: int = Field(ge=0)


class TrendPoint(BaseModel):
    bucket: str
    value: float


class BusinessTrendsResponse(BaseModel):
    range: str
    metric: BusinessMetric
    granularity: Literal["hour", "day"]
    points: list[TrendPoint]


# ── Aggregation helpers ───────────────────────────────────────────────

# Blended LLM cost per 1K tokens — matches agent_metrics_api assumptions.
_BLENDED_COST_PER_1K_TOKENS = 0.009
# Rough analyst fully-loaded cost ($/hour) used to monetize saved minutes.
_ANALYST_COST_PER_HOUR = 95.0


async def _compute_business_snapshot(
    repo: AgentRunRepository,
    org_id: str,
    range_str: str,
) -> dict[str, Any]:
    """Compute the 6 business KPIs from available aggregate data.

    Gracefully degrades to zero values when no data exists or when the
    repository lacks the aggregate helpers (e.g. fresh deployment). This
    is intentionally defensive — the dashboard must never error out for
    an empty tenant.
    """
    fleet: dict[str, Any] = {}
    aggregate_fleet = getattr(repo, "aggregate_fleet", None)
    if aggregate_fleet is not None:
        try:
            fleet = await aggregate_fleet(org_id=org_id, range_str=range_str) or {}
        except Exception as e:  # noqa: BLE001 — defensive: never break the dashboard
            logger.warning("business_metrics_fleet_aggregate_failed", error=str(e))
            fleet = {}

    total_runs = int(fleet.get("total_runs", 0))
    total_success = int(fleet.get("total_success", 0))
    total_failure = int(fleet.get("total_failure", 0))
    avg_duration_ms = float(fleet.get("avg_duration_ms", 0.0))
    total_tokens = int(fleet.get("total_tokens", 0))
    estimated_cost_usd = float(
        fleet.get("estimated_cost_usd", total_tokens / 1000.0 * _BLENDED_COST_PER_1K_TOKENS)
    )

    # Incidents ≈ successful runs (each agent run resolves one situation).
    # Failures surface as incidents still requiring human follow-up.
    incidents_total = total_runs
    incidents_auto_resolved = total_success

    # MTTD/MTTR — until event→alert→remediation timestamps flow through
    # the incident pipeline, derive from agent run duration. Detection is
    # modelled as 20% of the end-to-end cycle; remediation as the full run.
    mttr_seconds = avg_duration_ms / 1000.0
    mttd_seconds = mttr_seconds * 0.2

    # Cost per incident = LLM cost + proportional analyst review time.
    # Assume each failure requires 10 minutes of analyst attention.
    analyst_cost = (total_failure * (10.0 / 60.0)) * _ANALYST_COST_PER_HOUR
    total_cost = estimated_cost_usd + analyst_cost
    cost_per_incident = total_cost / incidents_total if incidents_total > 0 else 0.0

    # Agent ROI — percent of incidents handled without human escalation.
    agent_roi = (incidents_auto_resolved / incidents_total) * 100.0 if incidents_total > 0 else 0.0

    # Risk score — composite where lower success and higher failure drives
    # risk up. Ranges 0-100; placeholder until the risk_scoring agent is
    # wired in as the source of truth.
    if incidents_total > 0:
        failure_ratio = total_failure / incidents_total
        risk_score = min(100.0, 15.0 + failure_ratio * 70.0)
    else:
        risk_score = 0.0

    # Data volume — placeholder proxy via token throughput (tokens ≈ bytes/4,
    # scaled to GB). Replaced once the ingestion pipeline exposes byte counts.
    data_volume_gb = (total_tokens * 4.0) / (1024.0**3)

    return {
        "range": range_str,
        "mttd_seconds": round(mttd_seconds, 2),
        "mttr_seconds": round(mttr_seconds, 2),
        "cost_per_incident_usd": round(cost_per_incident, 4),
        "risk_score": round(risk_score, 2),
        "data_volume_gb": round(data_volume_gb, 6),
        "agent_roi_percent": round(agent_roi, 2),
        "incidents_total": incidents_total,
        "incidents_auto_resolved": incidents_auto_resolved,
    }


async def _compute_business_trends(
    repo: AgentRunRepository,
    org_id: str,
    range_str: str,
    metric: BusinessMetric,
) -> list[dict[str, Any]]:
    """Derive a trend series for a single business metric.

    Reuses the per-bucket time-series from ``AgentRunRepository`` when
    available. Returns an empty list when no data exists.
    """
    time_series = getattr(repo, "time_series_by_agent", None)
    if time_series is None:
        return []

    try:
        raw: list[dict[str, Any]] = (
            await time_series(
                org_id=org_id,
                range_str=range_str,
                agent_name=None,
            )
            or []
        )
    except Exception as e:  # noqa: BLE001 — defensive
        logger.warning("business_metrics_trend_aggregate_failed", error=str(e))
        return []

    # Collapse per-agent buckets into a single series (sum or weighted avg).
    merged: dict[str, dict[str, float]] = {}
    for point in raw:
        bucket = str(point.get("bucket") or "")
        if not bucket:
            continue
        slot = merged.setdefault(
            bucket,
            {"runs": 0.0, "success_rate_weighted": 0.0, "duration_weighted": 0.0, "tokens": 0.0},
        )
        runs = float(point.get("runs", 0))
        slot["runs"] += runs
        slot["success_rate_weighted"] += float(point.get("success_rate", 0.0)) * runs
        slot["duration_weighted"] += float(point.get("avg_duration_ms", 0.0)) * runs
        slot["tokens"] += float(point.get("total_tokens", 0))

    points: list[dict[str, Any]] = []
    for bucket in sorted(merged.keys()):
        slot = merged[bucket]
        runs = slot["runs"] or 0.0
        avg_duration_ms = (slot["duration_weighted"] / runs) if runs > 0 else 0.0
        success_rate = (slot["success_rate_weighted"] / runs) if runs > 0 else 0.0
        failure_rate = max(0.0, 1.0 - success_rate)
        tokens = slot["tokens"]

        if metric == "mttd":
            value = (avg_duration_ms / 1000.0) * 0.2
        elif metric == "mttr":
            value = avg_duration_ms / 1000.0
        elif metric == "cost":
            llm_cost = (tokens / 1000.0) * _BLENDED_COST_PER_1K_TOKENS
            analyst_cost = (runs * failure_rate * (10.0 / 60.0)) * _ANALYST_COST_PER_HOUR
            total_cost = llm_cost + analyst_cost
            value = (total_cost / runs) if runs > 0 else 0.0
        elif metric == "risk":
            value = min(100.0, 15.0 + failure_rate * 70.0) if runs > 0 else 0.0
        elif metric == "data_volume":
            value = (tokens * 4.0) / (1024.0**3)
        else:  # agent_roi
            value = success_rate * 100.0

        points.append({"bucket": bucket, "value": round(value, 4)})

    return points


# ── Endpoints ─────────────────────────────────────────────────────────


@router.get("", response_model=BusinessMetricsResponse)
async def get_business_metrics(
    range: BusinessRange = Query("24h", description="Time window for aggregation"),
    user: UserResponse = Depends(get_current_user),
) -> BusinessMetricsResponse:
    """Return the 6 business value KPIs for the caller's org."""
    repo = _get_run_repo()
    org_id = _extract_org_id(user)
    snapshot = await _compute_business_snapshot(repo, org_id=org_id, range_str=range)
    return BusinessMetricsResponse(**snapshot)


@router.get("/trends", response_model=BusinessTrendsResponse)
async def get_business_trends(
    metric: BusinessMetric = Query(..., description="Metric to plot"),
    range: BusinessRange = Query("7d", description="Time window for the trend chart"),
    user: UserResponse = Depends(get_current_user),
) -> BusinessTrendsResponse:
    """Return a bucketed time-series for one business metric."""
    repo = _get_run_repo()
    org_id = _extract_org_id(user)
    points = await _compute_business_trends(repo, org_id=org_id, range_str=range, metric=metric)
    granularity: Literal["hour", "day"] = "hour" if range == "24h" else "day"
    return BusinessTrendsResponse(
        range=range,
        metric=metric,
        granularity=granularity,
        points=[TrendPoint(**p) for p in points],
    )
