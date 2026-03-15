"""Helm Deployment Intelligence Engine —
assess upgrade readiness, detect helm misconfigurations,
compare deployment strategies."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DeploymentMode(StrEnum):
    DAEMONSET = "daemonset"
    DEPLOYMENT = "deployment"
    STATEFULSET = "statefulset"
    SIDECAR = "sidecar"


class ChartHealth(StrEnum):
    UP_TO_DATE = "up_to_date"
    MINOR_BEHIND = "minor_behind"
    MAJOR_BEHIND = "major_behind"
    UNSUPPORTED = "unsupported"


class MisconfigRisk(StrEnum):
    NONE = "none"
    PERFORMANCE = "performance"
    DATA_LOSS = "data_loss"
    SECURITY = "security"


# --- Models ---


class HelmDeploymentRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    release_name: str = ""
    deployment_mode: DeploymentMode = DeploymentMode.DEPLOYMENT
    chart_health: ChartHealth = ChartHealth.UP_TO_DATE
    misconfig_risk: MisconfigRisk = MisconfigRisk.NONE
    chart_version: str = ""
    deployed_version: str = ""
    replica_count: int = 1
    misconfig_count: int = 0
    upgrade_blocking_issues: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class HelmDeploymentAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    release_name: str = ""
    deployment_mode: DeploymentMode = DeploymentMode.DEPLOYMENT
    chart_health: ChartHealth = ChartHealth.UP_TO_DATE
    upgrade_ready: bool = True
    misconfig_detected: bool = False
    risk_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class HelmDeploymentReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    by_deployment_mode: dict[str, int] = Field(default_factory=dict)
    by_chart_health: dict[str, int] = Field(default_factory=dict)
    by_misconfig_risk: dict[str, int] = Field(default_factory=dict)
    blocking_releases: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class HelmDeploymentIntelligenceEngine:
    """Assess upgrade readiness, detect helm misconfigurations,
    compare deployment strategies."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[HelmDeploymentRecord] = []
        self._analyses: dict[str, HelmDeploymentAnalysis] = {}
        logger.info("helm_deployment_intelligence_engine.init", max_records=max_records)

    def add_record(
        self,
        release_name: str = "",
        deployment_mode: DeploymentMode = DeploymentMode.DEPLOYMENT,
        chart_health: ChartHealth = ChartHealth.UP_TO_DATE,
        misconfig_risk: MisconfigRisk = MisconfigRisk.NONE,
        chart_version: str = "",
        deployed_version: str = "",
        replica_count: int = 1,
        misconfig_count: int = 0,
        upgrade_blocking_issues: int = 0,
        description: str = "",
    ) -> HelmDeploymentRecord:
        record = HelmDeploymentRecord(
            release_name=release_name,
            deployment_mode=deployment_mode,
            chart_health=chart_health,
            misconfig_risk=misconfig_risk,
            chart_version=chart_version,
            deployed_version=deployed_version,
            replica_count=replica_count,
            misconfig_count=misconfig_count,
            upgrade_blocking_issues=upgrade_blocking_issues,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "helm_deployment.record_added",
            record_id=record.id,
            release_name=release_name,
        )
        return record

    def process(self, key: str) -> HelmDeploymentAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        risk_weights = {
            MisconfigRisk.NONE: 0.0,
            MisconfigRisk.PERFORMANCE: 1.0,
            MisconfigRisk.DATA_LOSS: 3.0,
            MisconfigRisk.SECURITY: 4.0,
        }
        chart_weights = {
            ChartHealth.UP_TO_DATE: 0.0,
            ChartHealth.MINOR_BEHIND: 10.0,
            ChartHealth.MAJOR_BEHIND: 30.0,
            ChartHealth.UNSUPPORTED: 50.0,
        }
        risk_score = round(
            risk_weights.get(rec.misconfig_risk, 0.0) * 10.0
            + chart_weights.get(rec.chart_health, 0.0)
            + rec.upgrade_blocking_issues * 5.0,
            2,
        )
        upgrade_ready = rec.upgrade_blocking_issues == 0 and rec.chart_health not in (
            ChartHealth.UNSUPPORTED,
        )
        misconfig_detected = rec.misconfig_count > 0 or rec.misconfig_risk != MisconfigRisk.NONE
        analysis = HelmDeploymentAnalysis(
            release_name=rec.release_name,
            deployment_mode=rec.deployment_mode,
            chart_health=rec.chart_health,
            upgrade_ready=upgrade_ready,
            misconfig_detected=misconfig_detected,
            risk_score=risk_score,
            description=(f"Release {rec.release_name} risk score {risk_score:.1f}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> HelmDeploymentReport:
        by_mode: dict[str, int] = {}
        by_health: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        blocking: list[str] = []
        for r in self._records:
            km = r.deployment_mode.value
            by_mode[km] = by_mode.get(km, 0) + 1
            kh = r.chart_health.value
            by_health[kh] = by_health.get(kh, 0) + 1
            kr = r.misconfig_risk.value
            by_risk[kr] = by_risk.get(kr, 0) + 1
            if r.upgrade_blocking_issues > 0 and r.release_name not in blocking:
                blocking.append(r.release_name)
        recs: list[str] = []
        unsupported = by_health.get("unsupported", 0)
        if unsupported > 0:
            recs.append(f"{unsupported} releases on unsupported chart versions")
        if blocking:
            recs.append(f"{len(blocking)} releases have upgrade-blocking issues")
        security_risk = by_risk.get("security", 0)
        if security_risk > 0:
            recs.append(f"{security_risk} releases with security misconfiguration risk")
        if not recs:
            recs.append("All Helm releases are healthy and up to date")
        return HelmDeploymentReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            by_deployment_mode=by_mode,
            by_chart_health=by_health,
            by_misconfig_risk=by_risk,
            blocking_releases=blocking[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        health_dist: dict[str, int] = {}
        for r in self._records:
            k = r.chart_health.value
            health_dist[k] = health_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "chart_health_distribution": health_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("helm_deployment_intelligence_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def assess_upgrade_readiness(self) -> list[dict[str, Any]]:
        """Assess upgrade readiness per release."""
        release_data: dict[str, list[HelmDeploymentRecord]] = {}
        for r in self._records:
            release_data.setdefault(r.release_name, []).append(r)
        results: list[dict[str, Any]] = []
        for rname, recs in release_data.items():
            total_blocking = sum(r.upgrade_blocking_issues for r in recs)
            unsupported = sum(1 for r in recs if r.chart_health == ChartHealth.UNSUPPORTED)
            ready = total_blocking == 0 and unsupported == 0
            results.append(
                {
                    "release_name": rname,
                    "upgrade_ready": ready,
                    "total_blocking_issues": total_blocking,
                    "unsupported_samples": unsupported,
                    "chart_health": recs[-1].chart_health.value,
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["total_blocking_issues"], reverse=True)
        return results

    def detect_helm_misconfigurations(self) -> list[dict[str, Any]]:
        """Detect releases with active misconfigurations."""
        release_data: dict[str, list[HelmDeploymentRecord]] = {}
        for r in self._records:
            release_data.setdefault(r.release_name, []).append(r)
        results: list[dict[str, Any]] = []
        for rname, recs in release_data.items():
            total_misconfigs = sum(r.misconfig_count for r in recs)
            security_risk = sum(1 for r in recs if r.misconfig_risk == MisconfigRisk.SECURITY)
            if total_misconfigs > 0 or security_risk > 0:
                results.append(
                    {
                        "release_name": rname,
                        "total_misconfigs": total_misconfigs,
                        "security_risk_samples": security_risk,
                        "misconfig_risk": recs[-1].misconfig_risk.value,
                        "deployment_mode": recs[-1].deployment_mode.value,
                    }
                )
        results.sort(key=lambda x: x["security_risk_samples"], reverse=True)
        return results

    def compare_deployment_strategies(self) -> list[dict[str, Any]]:
        """Compare risk and misconfig rates by deployment mode."""
        mode_data: dict[str, list[HelmDeploymentRecord]] = {}
        for r in self._records:
            mode_data.setdefault(r.deployment_mode.value, []).append(r)
        results: list[dict[str, Any]] = []
        for mode, recs in mode_data.items():
            avg_misconfigs = sum(r.misconfig_count for r in recs) / len(recs)
            avg_blocking = sum(r.upgrade_blocking_issues for r in recs) / len(recs)
            unsupported_pct = round(
                sum(1 for r in recs if r.chart_health == ChartHealth.UNSUPPORTED)
                / len(recs)
                * 100.0,
                2,
            )
            results.append(
                {
                    "deployment_mode": mode,
                    "avg_misconfig_count": round(avg_misconfigs, 2),
                    "avg_blocking_issues": round(avg_blocking, 2),
                    "unsupported_pct": unsupported_pct,
                    "total_releases": len({r.release_name for r in recs}),
                    "samples": len(recs),
                }
            )
        results.sort(key=lambda x: x["avg_misconfig_count"], reverse=True)
        return results
