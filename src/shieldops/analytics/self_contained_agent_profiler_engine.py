"""Self Contained Agent Profiler Engine —
profile agent dependencies, measure self-containment,
and recommend dependency reduction."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DependencyType(StrEnum):
    EXTERNAL_API = "external_api"
    DATABASE = "database"
    FILE_SYSTEM = "file_system"
    NETWORK_SERVICE = "network_service"


class ProfileMetric(StrEnum):
    STARTUP_TIME = "startup_time"
    MEMORY_FOOTPRINT = "memory_footprint"
    DEPENDENCY_COUNT = "dependency_count"
    COLD_START_LATENCY = "cold_start_latency"


class OptimizationTarget(StrEnum):
    MINIMIZE_DEPENDENCIES = "minimize_dependencies"
    REDUCE_FOOTPRINT = "reduce_footprint"
    SPEED_STARTUP = "speed_startup"
    ENABLE_OFFLINE = "enable_offline"


# --- Models ---


class SelfContainedAgentRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    dependency_type: DependencyType = DependencyType.EXTERNAL_API
    profile_metric: ProfileMetric = ProfileMetric.STARTUP_TIME
    optimization_target: OptimizationTarget = OptimizationTarget.MINIMIZE_DEPENDENCIES
    metric_value: float = 0.0
    dependency_count: int = 0
    is_optional: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SelfContainedAgentAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    self_containment_score: float = 0.0
    dependency_health: str = "healthy"
    primary_optimization_target: OptimizationTarget = OptimizationTarget.MINIMIZE_DEPENDENCIES
    optional_dependency_pct: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SelfContainedAgentReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    by_dependency_type: dict[str, int] = Field(default_factory=dict)
    by_profile_metric: dict[str, int] = Field(default_factory=dict)
    by_optimization_target: dict[str, int] = Field(default_factory=dict)
    top_self_contained: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class SelfContainedAgentProfilerEngine:
    """Profile agent dependencies, measure self-containment score,
    and recommend dependency reduction."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[SelfContainedAgentRecord] = []
        self._analyses: dict[str, SelfContainedAgentAnalysis] = {}
        logger.info(
            "self_contained_agent_profiler.init",
            max_records=max_records,
        )

    def add_record(
        self,
        agent_id: str = "",
        dependency_type: DependencyType = DependencyType.EXTERNAL_API,
        profile_metric: ProfileMetric = ProfileMetric.STARTUP_TIME,
        optimization_target: OptimizationTarget = OptimizationTarget.MINIMIZE_DEPENDENCIES,
        metric_value: float = 0.0,
        dependency_count: int = 0,
        is_optional: bool = False,
        description: str = "",
    ) -> SelfContainedAgentRecord:
        record = SelfContainedAgentRecord(
            agent_id=agent_id,
            dependency_type=dependency_type,
            profile_metric=profile_metric,
            optimization_target=optimization_target,
            metric_value=metric_value,
            dependency_count=dependency_count,
            is_optional=is_optional,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "self_contained_profiler.record_added",
            record_id=record.id,
            agent_id=agent_id,
        )
        return record

    def process(self, key: str) -> SelfContainedAgentAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        agent_recs = [r for r in self._records if r.agent_id == rec.agent_id]
        total_deps = sum(r.dependency_count for r in agent_recs)
        optional_deps = sum(r.dependency_count for r in agent_recs if r.is_optional)
        optional_pct = round(optional_deps / total_deps * 100.0 if total_deps > 0 else 0.0, 2)
        ext_api_count = sum(
            1 for r in agent_recs if r.dependency_type == DependencyType.EXTERNAL_API
        )
        containment_score = round(max(0.0, 100.0 - ext_api_count * 10.0 - total_deps * 2.0), 2)
        health = (
            "healthy"
            if containment_score >= 70
            else "degraded"
            if containment_score >= 40
            else "poor"
        )
        analysis = SelfContainedAgentAnalysis(
            agent_id=rec.agent_id,
            self_containment_score=containment_score,
            dependency_health=health,
            primary_optimization_target=rec.optimization_target,
            optional_dependency_pct=optional_pct,
            description=f"Agent {rec.agent_id} containment={containment_score}%",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> SelfContainedAgentReport:
        by_dt: dict[str, int] = {}
        by_pm: dict[str, int] = {}
        by_ot: dict[str, int] = {}
        for r in self._records:
            by_dt[r.dependency_type.value] = by_dt.get(r.dependency_type.value, 0) + 1
            by_pm[r.profile_metric.value] = by_pm.get(r.profile_metric.value, 0) + 1
            by_ot[r.optimization_target.value] = by_ot.get(r.optimization_target.value, 0) + 1
        agent_deps: dict[str, int] = {}
        for r in self._records:
            agent_deps[r.agent_id] = agent_deps.get(r.agent_id, 0) + r.dependency_count
        sorted_agents = sorted(agent_deps, key=lambda x: agent_deps[x])
        top_self_contained = sorted_agents[:10]
        recs_list: list[str] = []
        ext_api = by_dt.get("external_api", 0)
        if ext_api > 0:
            recs_list.append(f"{ext_api} external API dependencies — consider caching or mocking")
        if not recs_list:
            recs_list.append("Agent dependency profile is self-contained")
        return SelfContainedAgentReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            by_dependency_type=by_dt,
            by_profile_metric=by_pm,
            by_optimization_target=by_ot,
            top_self_contained=top_self_contained,
            recommendations=recs_list,
        )

    def get_stats(self) -> dict[str, Any]:
        dt_dist: dict[str, int] = {}
        for r in self._records:
            dt_dist[r.dependency_type.value] = dt_dist.get(r.dependency_type.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "dependency_type_distribution": dt_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("self_contained_agent_profiler.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def profile_agent_dependencies(self, agent_id: str) -> dict[str, Any]:
        """Profile all dependencies for an agent grouped by type."""
        agent_recs = [r for r in self._records if r.agent_id == agent_id]
        if not agent_recs:
            return {"agent_id": agent_id, "dependencies": {}}
        by_type: dict[str, dict[str, Any]] = {}
        for r in agent_recs:
            dep_type = r.dependency_type.value
            if dep_type not in by_type:
                by_type[dep_type] = {
                    "count": 0,
                    "optional_count": 0,
                    "total_metric": 0.0,
                }
            by_type[dep_type]["count"] += r.dependency_count
            if r.is_optional:
                by_type[dep_type]["optional_count"] += r.dependency_count
            by_type[dep_type]["total_metric"] += r.metric_value
        total_deps = sum(v["count"] for v in by_type.values())
        profile: list[dict[str, Any]] = []
        for dep_type, data in by_type.items():
            cnt = data["count"]
            profile.append(
                {
                    "dependency_type": dep_type,
                    "count": cnt,
                    "optional_count": data["optional_count"],
                    "required_count": cnt - data["optional_count"],
                    "share_pct": round(cnt / total_deps * 100.0 if total_deps > 0 else 0.0, 2),
                    "avg_metric": round(data["total_metric"] / cnt if cnt > 0 else 0.0, 4),
                }
            )
        profile.sort(key=lambda x: x["count"], reverse=True)
        return {
            "agent_id": agent_id,
            "total_dependencies": total_deps,
            "dependency_profile": profile,
            "dependency_types": len(by_type),
        }

    def measure_self_containment_score(self) -> list[dict[str, Any]]:
        """Measure self-containment score for all agents."""
        agent_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            aid = r.agent_id
            if aid not in agent_data:
                agent_data[aid] = {
                    "total_deps": 0,
                    "ext_api_deps": 0,
                    "optional_deps": 0,
                }
            agent_data[aid]["total_deps"] += r.dependency_count
            if r.dependency_type == DependencyType.EXTERNAL_API:
                agent_data[aid]["ext_api_deps"] += r.dependency_count
            if r.is_optional:
                agent_data[aid]["optional_deps"] += r.dependency_count
        results: list[dict[str, Any]] = []
        for aid, data in agent_data.items():
            total = data["total_deps"]
            ext = data["ext_api_deps"]
            opt = data["optional_deps"]
            score = max(0.0, 100.0 - ext * 10.0 - (total - opt) * 2.0)
            results.append(
                {
                    "agent_id": aid,
                    "self_containment_score": round(score, 2),
                    "total_dependencies": total,
                    "external_api_dependencies": ext,
                    "optional_dependencies": opt,
                    "offline_capable": ext == 0,
                }
            )
        results.sort(key=lambda x: x["self_containment_score"], reverse=True)
        return results

    def recommend_dependency_reduction(self) -> list[dict[str, Any]]:
        """Recommend specific dependency reductions per agent."""
        agent_recs_map: dict[str, list[SelfContainedAgentRecord]] = {}
        for r in self._records:
            agent_recs_map.setdefault(r.agent_id, []).append(r)
        results: list[dict[str, Any]] = []
        for aid, recs in agent_recs_map.items():
            total_deps = sum(r.dependency_count for r in recs)
            removable = [r for r in recs if r.is_optional]
            removable_count = sum(r.dependency_count for r in removable)
            ext_api_recs = [r for r in recs if r.dependency_type == DependencyType.EXTERNAL_API]
            suggestions: list[str] = []
            if removable_count > 0:
                suggestions.append(f"Remove {removable_count} optional dependencies")
            if ext_api_recs:
                suggestions.append(
                    f"Cache or mock {len(ext_api_recs)} external API calls for offline mode"
                )
            net_recs = [r for r in recs if r.dependency_type == DependencyType.NETWORK_SERVICE]
            if net_recs:
                suggestions.append(f"Evaluate {len(net_recs)} network services for bundling")
            target_deps = max(0, total_deps - removable_count)
            results.append(
                {
                    "agent_id": aid,
                    "current_dep_count": total_deps,
                    "removable_dep_count": removable_count,
                    "target_dep_count": target_deps,
                    "suggestions": suggestions,
                    "priority": (
                        "high" if total_deps > 20 else "medium" if total_deps > 10 else "low"
                    ),
                }
            )
        results.sort(key=lambda x: x["current_dep_count"], reverse=True)
        return results
