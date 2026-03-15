"""Attack Surface Continuous Scorer Engine —
continuously score attack surface risk, track exposed services,
vulnerabilities, and misconfigurations."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SurfaceComponent(StrEnum):
    EXTERNAL_SERVICE = "external_service"
    INTERNAL_SERVICE = "internal_service"
    API_ENDPOINT = "api_endpoint"
    CLOUD_RESOURCE = "cloud_resource"


class ExposureLevel(StrEnum):
    INTERNET_FACING = "internet_facing"
    VPN_ONLY = "vpn_only"
    INTERNAL = "internal"
    AIR_GAPPED = "air_gapped"


class RiskChange(StrEnum):
    INCREASED = "increased"
    DECREASED = "decreased"
    UNCHANGED = "unchanged"
    NEW_EXPOSURE = "new_exposure"


# --- Models ---


class AttackSurfaceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    component_id: str = ""
    component_name: str = ""
    surface_component: SurfaceComponent = SurfaceComponent.INTERNAL_SERVICE
    exposure_level: ExposureLevel = ExposureLevel.INTERNAL
    risk_change: RiskChange = RiskChange.UNCHANGED
    risk_score: float = 0.0
    vulnerability_count: int = 0
    misconfiguration_count: int = 0
    last_scan_at: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AttackSurfaceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    component_id: str = ""
    surface_component: SurfaceComponent = SurfaceComponent.INTERNAL_SERVICE
    exposure_level: ExposureLevel = ExposureLevel.INTERNAL
    composite_risk: float = 0.0
    remediation_priority: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AttackSurfaceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    aggregate_risk_score: float = 0.0
    by_surface_component: dict[str, int] = Field(default_factory=dict)
    by_exposure_level: dict[str, int] = Field(default_factory=dict)
    by_risk_change: dict[str, int] = Field(default_factory=dict)
    critical_components: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AttackSurfaceContinuousScorerEngine:
    """Continuously score attack surface risk — track exposed services,
    vulnerabilities, and misconfigurations."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[AttackSurfaceRecord] = []
        self._analyses: dict[str, AttackSurfaceAnalysis] = {}
        logger.info(
            "attack_surface_continuous_scorer_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        component_id: str = "",
        component_name: str = "",
        surface_component: SurfaceComponent = SurfaceComponent.INTERNAL_SERVICE,
        exposure_level: ExposureLevel = ExposureLevel.INTERNAL,
        risk_change: RiskChange = RiskChange.UNCHANGED,
        risk_score: float = 0.0,
        vulnerability_count: int = 0,
        misconfiguration_count: int = 0,
        last_scan_at: float = 0.0,
        description: str = "",
    ) -> AttackSurfaceRecord:
        record = AttackSurfaceRecord(
            component_id=component_id,
            component_name=component_name,
            surface_component=surface_component,
            exposure_level=exposure_level,
            risk_change=risk_change,
            risk_score=risk_score,
            vulnerability_count=vulnerability_count,
            misconfiguration_count=misconfiguration_count,
            last_scan_at=last_scan_at,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "attack_surface.record_added",
            record_id=record.id,
            component_id=component_id,
        )
        return record

    def process(self, key: str) -> AttackSurfaceAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        exposure_weight = {
            ExposureLevel.INTERNET_FACING: 1.0,
            ExposureLevel.VPN_ONLY: 0.6,
            ExposureLevel.INTERNAL: 0.3,
            ExposureLevel.AIR_GAPPED: 0.1,
        }
        weight = exposure_weight.get(rec.exposure_level, 0.5)
        vuln_factor = min(rec.vulnerability_count / 10.0, 1.0)
        misconfig_factor = min(rec.misconfiguration_count / 5.0, 1.0)
        composite = round(
            (rec.risk_score * 0.4 + vuln_factor * 0.3 + misconfig_factor * 0.3) * weight * 100,
            2,
        )
        priority = 1 if composite >= 70 else 2 if composite >= 40 else 3
        analysis = AttackSurfaceAnalysis(
            component_id=rec.component_id,
            surface_component=rec.surface_component,
            exposure_level=rec.exposure_level,
            composite_risk=composite,
            remediation_priority=priority,
            description=(f"Component {rec.component_id} composite_risk={composite}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> AttackSurfaceReport:
        by_comp: dict[str, int] = {}
        by_exp: dict[str, int] = {}
        by_change: dict[str, int] = {}
        scores: list[float] = []
        for r in self._records:
            by_comp[r.surface_component.value] = by_comp.get(r.surface_component.value, 0) + 1
            by_exp[r.exposure_level.value] = by_exp.get(r.exposure_level.value, 0) + 1
            by_change[r.risk_change.value] = by_change.get(r.risk_change.value, 0) + 1
            scores.append(r.risk_score)
        agg_score = round(sum(scores) / len(scores), 4) if scores else 0.0
        critical = list(
            {
                r.component_id
                for r in self._records
                if r.risk_score > 0.7
                and r.exposure_level == ExposureLevel.INTERNET_FACING
                and r.component_id
            }
        )[:10]
        recs: list[str] = []
        if critical:
            recs.append(f"{len(critical)} internet-facing components with high risk")
        new_exposures = sum(1 for r in self._records if r.risk_change == RiskChange.NEW_EXPOSURE)
        if new_exposures:
            recs.append(f"{new_exposures} new exposures detected")
        if not recs:
            recs.append("Attack surface scoring within acceptable parameters")
        return AttackSurfaceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            aggregate_risk_score=agg_score,
            by_surface_component=by_comp,
            by_exposure_level=by_exp,
            by_risk_change=by_change,
            critical_components=critical,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        comp_dist: dict[str, int] = {}
        for r in self._records:
            comp_dist[r.surface_component.value] = comp_dist.get(r.surface_component.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "surface_component_distribution": comp_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("attack_surface_continuous_scorer_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def compute_attack_surface_score(self) -> dict[str, Any]:
        """Aggregate risk score across all components."""
        if not self._records:
            return {
                "total_components": 0,
                "aggregate_score": 0.0,
                "internet_facing_score": 0.0,
                "internal_score": 0.0,
                "grade": "no_data",
            }
        exposure_weight = {
            ExposureLevel.INTERNET_FACING: 1.0,
            ExposureLevel.VPN_ONLY: 0.6,
            ExposureLevel.INTERNAL: 0.3,
            ExposureLevel.AIR_GAPPED: 0.1,
        }
        weighted_scores: list[float] = []
        inet_scores: list[float] = []
        internal_scores: list[float] = []
        for r in self._records:
            w = exposure_weight.get(r.exposure_level, 0.5)
            ws = r.risk_score * w
            weighted_scores.append(ws)
            if r.exposure_level == ExposureLevel.INTERNET_FACING:
                inet_scores.append(r.risk_score)
            elif r.exposure_level == ExposureLevel.INTERNAL:
                internal_scores.append(r.risk_score)
        agg = round(sum(weighted_scores) / len(weighted_scores) * 100, 2)
        inet_avg = round(sum(inet_scores) / len(inet_scores) * 100, 2) if inet_scores else 0.0
        int_avg = (
            round(sum(internal_scores) / len(internal_scores) * 100, 2) if internal_scores else 0.0
        )
        if agg >= 70:
            grade = "critical"
        elif agg >= 40:
            grade = "high"
        elif agg >= 20:
            grade = "moderate"
        else:
            grade = "low"
        return {
            "total_components": len(self._records),
            "aggregate_score": agg,
            "internet_facing_score": inet_avg,
            "internal_score": int_avg,
            "grade": grade,
        }

    def detect_exposure_changes(self) -> list[dict[str, Any]]:
        """Identify new or changed exposures since last scan."""
        changes: list[dict[str, Any]] = []
        for r in self._records:
            if r.risk_change in (
                RiskChange.INCREASED,
                RiskChange.NEW_EXPOSURE,
            ):
                changes.append(
                    {
                        "component_id": r.component_id,
                        "component_name": r.component_name,
                        "surface_component": r.surface_component.value,
                        "exposure_level": r.exposure_level.value,
                        "risk_change": r.risk_change.value,
                        "risk_score": r.risk_score,
                        "vulnerability_count": r.vulnerability_count,
                        "severity": (
                            "critical"
                            if r.risk_change == RiskChange.NEW_EXPOSURE
                            and r.exposure_level == ExposureLevel.INTERNET_FACING
                            else "high"
                            if r.risk_score > 0.7
                            else "medium"
                        ),
                    }
                )
        changes.sort(key=lambda x: x["risk_score"], reverse=True)
        return changes

    def prioritize_remediation(self) -> list[dict[str, Any]]:
        """Rank components by risk for remediation priority."""
        component_data: dict[str, list[AttackSurfaceRecord]] = {}
        for r in self._records:
            component_data.setdefault(r.component_id, []).append(r)
        results: list[dict[str, Any]] = []
        exposure_weight = {
            ExposureLevel.INTERNET_FACING: 1.0,
            ExposureLevel.VPN_ONLY: 0.6,
            ExposureLevel.INTERNAL: 0.3,
            ExposureLevel.AIR_GAPPED: 0.1,
        }
        for cid, recs in component_data.items():
            latest = recs[-1]
            w = exposure_weight.get(latest.exposure_level, 0.5)
            priority_score = round(
                (
                    latest.risk_score * 0.5
                    + min(latest.vulnerability_count / 10, 1.0) * 0.3
                    + min(latest.misconfiguration_count / 5, 1.0) * 0.2
                )
                * w
                * 100,
                2,
            )
            results.append(
                {
                    "component_id": cid,
                    "component_name": latest.component_name,
                    "exposure_level": latest.exposure_level.value,
                    "priority_score": priority_score,
                    "vulnerability_count": latest.vulnerability_count,
                    "misconfiguration_count": latest.misconfiguration_count,
                    "risk_score": latest.risk_score,
                    "remediation_urgency": (
                        "immediate"
                        if priority_score >= 70
                        else "high"
                        if priority_score >= 40
                        else "normal"
                    ),
                }
            )
        results.sort(key=lambda x: x["priority_score"], reverse=True)
        return results
