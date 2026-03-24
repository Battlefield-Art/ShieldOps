"""OTelResourceAttributionEngine — attribute telemetry costs (storage, processing,
export) to individual services/teams."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ResourceCostType(StrEnum):
    STORAGE = "storage"
    PROCESSING = "processing"
    EXPORT = "export"
    INGESTION = "ingestion"


class AttributionMethod(StrEnum):
    PROPORTIONAL = "proportional"
    FIXED_ALLOCATION = "fixed_allocation"
    USAGE_BASED = "usage_based"
    TIERED = "tiered"


class CostTrend(StrEnum):
    INCREASING = "increasing"
    STABLE = "stable"
    DECREASING = "decreasing"
    ANOMALOUS = "anomalous"


# --- Models ---


class ResourceAttributionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str = ""
    resource_cost_type: ResourceCostType = ResourceCostType.STORAGE
    attribution_method: AttributionMethod = AttributionMethod.USAGE_BASED
    cost_trend: CostTrend = CostTrend.STABLE
    cost_usd: float = 0.0
    volume_bytes: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ResourceAttributionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str = ""
    total_cost_usd: float = 0.0
    avg_cost_usd: float = 0.0
    cost_trend: CostTrend = CostTrend.STABLE
    is_outlier: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ResourceAttributionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    total_cost_usd: float = 0.0
    avg_cost_per_service_usd: float = 0.0
    by_resource_cost_type: dict[str, int] = Field(default_factory=dict)
    by_attribution_method: dict[str, int] = Field(default_factory=dict)
    by_cost_trend: dict[str, int] = Field(default_factory=dict)
    cost_outlier_services: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OTelResourceAttributionEngine:
    """Attribute telemetry costs to individual services and teams."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 500.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ResourceAttributionRecord] = []
        self._analyses: list[ResourceAttributionAnalysis] = []
        logger.info(
            "otel.resource.attribution.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        service_name: str,
        resource_cost_type: ResourceCostType = ResourceCostType.STORAGE,
        attribution_method: AttributionMethod = AttributionMethod.USAGE_BASED,
        cost_trend: CostTrend = CostTrend.STABLE,
        cost_usd: float = 0.0,
        volume_bytes: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ResourceAttributionRecord:
        record = ResourceAttributionRecord(
            service_name=service_name,
            resource_cost_type=resource_cost_type,
            attribution_method=attribution_method,
            cost_trend=cost_trend,
            cost_usd=cost_usd,
            volume_bytes=volume_bytes,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel.resource.attribution.record_added",
            record_id=record.id,
            service_name=service_name,
            resource_cost_type=resource_cost_type.value,
        )
        return record

    def get_record(self, record_id: str) -> ResourceAttributionRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        service_name: str | None = None,
        resource_cost_type: ResourceCostType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ResourceAttributionRecord]:
        results = list(self._records)
        if service_name is not None:
            results = [r for r in results if r.service_name == service_name]
        if resource_cost_type is not None:
            results = [r for r in results if r.resource_cost_type == resource_cost_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, service_name: str) -> ResourceAttributionAnalysis | None:
        records = [r for r in self._records if r.service_name == service_name]
        if not records:
            return None
        costs = [r.cost_usd for r in records]
        total_cost = round(sum(costs), 2)
        avg_cost = round(total_cost / len(costs), 2)
        # Determine trend from records
        if len(records) >= 3:
            mid = len(records) // 2
            older_avg = sum(r.cost_usd for r in records[:mid]) / mid
            recent_avg = sum(r.cost_usd for r in records[mid:]) / (len(records) - mid)
            change_pct = (recent_avg - older_avg) / older_avg * 100 if older_avg > 0 else 0.0
            if abs(change_pct) > 100:
                trend = CostTrend.ANOMALOUS
            elif change_pct > 20:
                trend = CostTrend.INCREASING
            elif change_pct < -20:
                trend = CostTrend.DECREASING
            else:
                trend = CostTrend.STABLE
        else:
            trend = CostTrend.STABLE
        is_outlier = avg_cost > self._threshold
        analysis = ResourceAttributionAnalysis(
            service_name=service_name,
            total_cost_usd=total_cost,
            avg_cost_usd=avg_cost,
            cost_trend=trend,
            is_outlier=is_outlier,
            description=(
                f"Attribution for {service_name}: total=${total_cost}, "
                f"avg=${avg_cost}, trend={trend.value}"
            ),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel.resource.attribution.processed",
            service_name=service_name,
            total_cost_usd=total_cost,
            trend=trend.value,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_service_cost(self, service_name: str) -> dict[str, Any]:
        """Compute total telemetry cost for a service."""
        records = [r for r in self._records if r.service_name == service_name]
        if not records:
            return {"service_name": service_name, "status": "no_data"}
        total_cost = round(sum(r.cost_usd for r in records), 2)
        avg_cost = round(total_cost / len(records), 2)
        by_type: dict[str, float] = {}
        for r in records:
            key = r.resource_cost_type.value
            by_type[key] = round(by_type.get(key, 0.0) + r.cost_usd, 2)
        total_volume = round(sum(r.volume_bytes for r in records), 2)
        return {
            "service_name": service_name,
            "total_cost_usd": total_cost,
            "avg_cost_usd": avg_cost,
            "cost_by_type": by_type,
            "total_volume_bytes": total_volume,
            "record_count": len(records),
            "exceeds_threshold": avg_cost > self._threshold,
        }

    def identify_cost_outliers(self) -> list[dict[str, Any]]:
        """Find services with disproportionate telemetry costs."""
        by_service: dict[str, list[float]] = {}
        for r in self._records:
            by_service.setdefault(r.service_name, []).append(r.cost_usd)
        if not by_service:
            return []
        all_avgs = []
        svc_data: list[dict[str, Any]] = []
        for svc, costs in by_service.items():
            avg_cost = sum(costs) / len(costs)
            all_avgs.append(avg_cost)
            svc_data.append(
                {
                    "service_name": svc,
                    "avg_cost_usd": round(avg_cost, 2),
                    "total_cost_usd": round(sum(costs), 2),
                    "record_count": len(costs),
                }
            )
        global_avg = sum(all_avgs) / len(all_avgs) if all_avgs else 0.0
        results: list[dict[str, Any]] = []
        for item in svc_data:
            if item["avg_cost_usd"] > self._threshold or (
                global_avg > 0 and item["avg_cost_usd"] > global_avg * 3
            ):
                item["global_avg_cost_usd"] = round(global_avg, 2)
                item["ratio_to_avg"] = (
                    round(item["avg_cost_usd"] / global_avg, 2) if global_avg > 0 else 0.0
                )
                results.append(item)
        results.sort(key=lambda x: x["total_cost_usd"], reverse=True)
        return results

    def generate_chargeback_report(self) -> list[dict[str, Any]]:
        """Generate cost attribution report for chargeback."""
        by_team: dict[str, dict[str, float]] = {}
        for r in self._records:
            team_key = r.team or "unassigned"
            if team_key not in by_team:
                by_team[team_key] = {"total_cost": 0.0, "total_volume": 0.0, "count": 0}
            by_team[team_key]["total_cost"] += r.cost_usd
            by_team[team_key]["total_volume"] += r.volume_bytes
            by_team[team_key]["count"] += 1
        total_cost = sum(d["total_cost"] for d in by_team.values())
        results: list[dict[str, Any]] = []
        for team, data in by_team.items():
            pct = round((data["total_cost"] / total_cost) * 100, 2) if total_cost > 0 else 0.0
            results.append(
                {
                    "team": team,
                    "total_cost_usd": round(data["total_cost"], 2),
                    "total_volume_bytes": round(data["total_volume"], 2),
                    "record_count": int(data["count"]),
                    "cost_share_pct": pct,
                }
            )
        results.sort(key=lambda x: x["total_cost_usd"], reverse=True)
        return results

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> ResourceAttributionReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.resource_cost_type.value] = by_e1.get(r.resource_cost_type.value, 0) + 1
            by_e2[r.attribution_method.value] = by_e2.get(r.attribution_method.value, 0) + 1
            by_e3[r.cost_trend.value] = by_e3.get(r.cost_trend.value, 0) + 1
        costs = [r.cost_usd for r in self._records]
        total_cost = round(sum(costs), 2) if costs else 0.0
        unique_services = {r.service_name for r in self._records}
        avg_per_svc = round(total_cost / len(unique_services), 2) if unique_services else 0.0
        outliers = self.identify_cost_outliers()
        outlier_names = [o["service_name"] for o in outliers[:5]]
        recs: list[str] = []
        if outliers:
            recs.append(f"{len(outliers)} service(s) have disproportionate telemetry costs")
        if avg_per_svc > self._threshold and self._records:
            recs.append(
                f"Avg cost per service ${avg_per_svc} exceeds threshold (${self._threshold})"
            )
        if not recs:
            recs.append("Telemetry cost attribution is within acceptable bounds")
        return ResourceAttributionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            total_cost_usd=total_cost,
            avg_cost_per_service_usd=avg_per_svc,
            by_resource_cost_type=by_e1,
            by_attribution_method=by_e2,
            by_cost_trend=by_e3,
            cost_outlier_services=outlier_names,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel.resource.attribution.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            key = r.resource_cost_type.value
            type_dist[key] = type_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "resource_cost_type_distribution": type_dist,
            "unique_services": len({r.service_name for r in self._records}),
            "unique_teams": len({r.team for r in self._records}),
        }
