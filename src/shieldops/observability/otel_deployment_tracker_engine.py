"""OtelDeploymentTrackerEngine — Track OTel Collector deployment lifecycle across clusters."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DeploymentPhase(StrEnum):
    PLANNED = "planned"
    DEPLOYING = "deploying"
    RUNNING = "running"
    DEGRADED = "degraded"
    FAILED = "failed"


class DeploymentType(StrEnum):
    DAEMONSET = "daemonset"
    DEPLOYMENT = "deployment"
    SIDECAR = "sidecar"


class ClusterRegion(StrEnum):
    US_EAST = "us_east"
    US_WEST = "us_west"
    EU_WEST = "eu_west"
    AP_SOUTH = "ap_south"


# --- Models ---


class OtelDeploymentTrackerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    deployment_phase: DeploymentPhase = DeploymentPhase.PLANNED
    deployment_type: DeploymentType = DeploymentType.DAEMONSET
    cluster_region: ClusterRegion = ClusterRegion.US_EAST
    score: float = 0.0
    replica_count: int = 0
    config_version: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelDeploymentTrackerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    deployment_phase: DeploymentPhase = DeploymentPhase.PLANNED
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class OtelDeploymentTrackerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_deployment_phase: dict[str, int] = Field(default_factory=dict)
    by_deployment_type: dict[str, int] = Field(default_factory=dict)
    by_cluster_region: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class OtelDeploymentTrackerEngine:
    """Track OTel Collector deployment lifecycle across clusters."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[OtelDeploymentTrackerRecord] = []
        self._analyses: list[OtelDeploymentTrackerAnalysis] = []
        logger.info(
            "otel_deployment_tracker_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        deployment_phase: DeploymentPhase = DeploymentPhase.PLANNED,
        deployment_type: DeploymentType = DeploymentType.DAEMONSET,
        cluster_region: ClusterRegion = ClusterRegion.US_EAST,
        score: float = 0.0,
        replica_count: int = 0,
        config_version: str = "",
        service: str = "",
        team: str = "",
    ) -> OtelDeploymentTrackerRecord:
        record = OtelDeploymentTrackerRecord(
            name=name,
            deployment_phase=deployment_phase,
            deployment_type=deployment_type,
            cluster_region=cluster_region,
            score=score,
            replica_count=replica_count,
            config_version=config_version,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "otel_deployment_tracker_engine.record_added",
            record_id=record.id,
            name=name,
            deployment_phase=deployment_phase.value,
            deployment_type=deployment_type.value,
        )
        return record

    def get_record(self, record_id: str) -> OtelDeploymentTrackerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        deployment_phase: DeploymentPhase | None = None,
        deployment_type: DeploymentType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[OtelDeploymentTrackerRecord]:
        results = list(self._records)
        if deployment_phase is not None:
            results = [r for r in results if r.deployment_phase == deployment_phase]
        if deployment_type is not None:
            results = [r for r in results if r.deployment_type == deployment_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        deployment_phase: DeploymentPhase = DeploymentPhase.PLANNED,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> OtelDeploymentTrackerAnalysis:
        analysis = OtelDeploymentTrackerAnalysis(
            name=name,
            deployment_phase=deployment_phase,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "otel_deployment_tracker_engine.analysis_added",
            name=name,
            deployment_phase=deployment_phase.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def track_deployment_health(self) -> list[dict[str, Any]]:
        """Track health status of deployments across clusters."""
        cluster_health: dict[str, dict[str, int]] = {}
        for r in self._records:
            region = r.cluster_region.value
            cluster_health.setdefault(region, {})
            phase = r.deployment_phase.value
            cluster_health[region][phase] = cluster_health[region].get(phase, 0) + 1
        results: list[dict[str, Any]] = []
        for region, phases in cluster_health.items():
            total = sum(phases.values())
            healthy = phases.get("running", 0)
            health_pct = round(healthy / total * 100, 1) if total else 0.0
            results.append(
                {
                    "region": region,
                    "total_deployments": total,
                    "healthy": healthy,
                    "degraded": phases.get("degraded", 0),
                    "failed": phases.get("failed", 0),
                    "health_pct": health_pct,
                }
            )
        return sorted(results, key=lambda x: x["health_pct"])

    def detect_config_drift_across_clusters(self) -> list[dict[str, Any]]:
        """Detect config version drift across clusters for same service."""
        svc_versions: dict[str, dict[str, set[str]]] = {}
        for r in self._records:
            svc_versions.setdefault(r.service, {})
            region = r.cluster_region.value
            svc_versions[r.service].setdefault(region, set()).add(r.config_version)
        drifts: list[dict[str, Any]] = []
        for svc, regions in svc_versions.items():
            all_versions: set[str] = set()
            for vs in regions.values():
                all_versions.update(vs)
            if len(all_versions) > 1:
                drifts.append(
                    {
                        "service": svc,
                        "regions": {r: sorted(v) for r, v in regions.items()},
                        "unique_versions": sorted(all_versions),
                        "drift_count": len(all_versions),
                        "severity": "high" if len(all_versions) > 2 else "medium",
                    }
                )
        return sorted(drifts, key=lambda x: x["drift_count"], reverse=True)

    def recommend_deployment_upgrades(self) -> list[dict[str, Any]]:
        """Recommend deployment upgrades based on phase and score."""
        recommendations: list[dict[str, Any]] = []
        failed = [r for r in self._records if r.deployment_phase == DeploymentPhase.FAILED]
        for r in failed:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "region": r.cluster_region.value,
                    "issue": "deployment_failed",
                    "priority": "critical",
                    "suggestion": f"Redeploy {r.name} in {r.cluster_region.value}",
                }
            )
        degraded = [r for r in self._records if r.deployment_phase == DeploymentPhase.DEGRADED]
        for r in degraded:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "region": r.cluster_region.value,
                    "issue": "deployment_degraded",
                    "priority": "high",
                    "suggestion": f"Investigate degraded deployment {r.name}",
                }
            )
        low_score = [
            r
            for r in self._records
            if r.score < self._threshold
            and r.deployment_phase not in (DeploymentPhase.FAILED, DeploymentPhase.DEGRADED)
        ]
        for r in low_score:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "region": r.cluster_region.value,
                    "issue": "low_score",
                    "priority": "medium",
                    "suggestion": f"Upgrade deployment config (score: {r.score})",
                }
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(recommendations, key=lambda x: priority_order.get(x["priority"], 3))

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.deployment_phase.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "deployment_phase": r.deployment_phase.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> OtelDeploymentTrackerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.deployment_phase.value] = by_e1.get(r.deployment_phase.value, 0) + 1
            by_e2[r.deployment_type.value] = by_e2.get(r.deployment_type.value, 0) + 1
            by_e3[r.cluster_region.value] = by_e3.get(r.cluster_region.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("OTel Deployment Tracker Engine is healthy")
        return OtelDeploymentTrackerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_deployment_phase=by_e1,
            by_deployment_type=by_e2,
            by_cluster_region=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("otel_deployment_tracker_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.deployment_phase.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "deployment_phase_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
