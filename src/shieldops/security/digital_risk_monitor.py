"""Digital Risk Monitor — dark web monitoring, brand abuse, credential leak tracking."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RiskSurface(StrEnum):
    DARK_WEB = "dark_web"
    SOCIAL_MEDIA = "social_media"
    PASTE_SITES = "paste_sites"
    CODE_REPOS = "code_repos"
    DEEP_WEB = "deep_web"


class ExposureType(StrEnum):
    CREDENTIAL_LEAK = "credential_leak"
    BRAND_ABUSE = "brand_abuse"
    DATA_SALE = "data_sale"
    DOMAIN_SPOOF = "domain_spoof"
    EXECUTIVE_IMPERSONATION = "executive_impersonation"


class MonitoringFrequency(StrEnum):
    REALTIME = "realtime"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    ON_DEMAND = "on_demand"


# --- Models ---


class RiskRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    risk_name: str = ""
    risk_surface: RiskSurface = RiskSurface.DARK_WEB
    exposure_type: ExposureType = ExposureType.CREDENTIAL_LEAK
    monitoring_frequency: MonitoringFrequency = MonitoringFrequency.DAILY
    risk_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    risk_name: str = ""
    risk_surface: RiskSurface = RiskSurface.DARK_WEB
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    high_risk_count: int = 0
    avg_risk_score: float = 0.0
    by_surface: dict[str, int] = Field(default_factory=dict)
    by_exposure: dict[str, int] = Field(default_factory=dict)
    by_frequency: dict[str, int] = Field(default_factory=dict)
    top_risks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class DigitalRiskMonitor:
    """Dark web monitoring, brand abuse detection, credential leak tracking."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._risk_threshold = risk_threshold
        self._records: list[RiskRecord] = []
        self._analyses: list[RiskAnalysis] = []
        logger.info(
            "digital_risk_monitor.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    # -- record / get / list ----------------------------

    def add_record(
        self,
        risk_name: str,
        risk_surface: RiskSurface = (RiskSurface.DARK_WEB),
        exposure_type: ExposureType = (ExposureType.CREDENTIAL_LEAK),
        monitoring_frequency: MonitoringFrequency = (MonitoringFrequency.DAILY),
        risk_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> RiskRecord:
        record = RiskRecord(
            risk_name=risk_name,
            risk_surface=risk_surface,
            exposure_type=exposure_type,
            monitoring_frequency=monitoring_frequency,
            risk_score=risk_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "digital_risk_monitor.record_added",
            record_id=record.id,
            risk_name=risk_name,
            risk_surface=risk_surface.value,
        )
        return record

    def get_record(self, record_id: str) -> RiskRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        risk_surface: RiskSurface | None = None,
        exposure_type: ExposureType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[RiskRecord]:
        results = list(self._records)
        if risk_surface is not None:
            results = [r for r in results if r.risk_surface == risk_surface]
        if exposure_type is not None:
            results = [r for r in results if r.exposure_type == exposure_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        risk_name: str,
        risk_surface: RiskSurface = (RiskSurface.DARK_WEB),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> RiskAnalysis:
        analysis = RiskAnalysis(
            risk_name=risk_name,
            risk_surface=risk_surface,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "digital_risk_monitor.analysis_added",
            risk_name=risk_name,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ------------------------------

    def monitor_dark_web(self) -> dict[str, Any]:
        """Group by risk_surface; return count and avg risk_score."""
        surface_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.risk_surface.value
            surface_data.setdefault(key, []).append(r.risk_score)
        result: dict[str, Any] = {}
        for surface, scores in surface_data.items():
            result[surface] = {
                "count": len(scores),
                "avg_risk_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def detect_brand_abuse(
        self,
    ) -> list[dict[str, Any]]:
        """Return brand abuse records above threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.exposure_type == ExposureType.BRAND_ABUSE and r.risk_score >= self._risk_threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "risk_name": r.risk_name,
                        "risk_surface": (r.risk_surface.value),
                        "risk_score": r.risk_score,
                        "service": r.service,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["risk_score"],
            reverse=True,
        )

    def track_credential_leaks(
        self,
    ) -> list[dict[str, Any]]:
        """Group by service for credential leak exposures."""
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            if r.exposure_type == ExposureType.CREDENTIAL_LEAK:
                svc_scores.setdefault(r.service, []).append(r.risk_score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_risk_score": round(sum(scores) / len(scores), 2),
                    "leak_count": len(scores),
                }
            )
        results.sort(
            key=lambda x: x["avg_risk_score"],
            reverse=True,
        )
        return results

    # -- report / stats ---------------------------------

    def generate_report(self) -> RiskReport:
        by_surface: dict[str, int] = {}
        by_exposure: dict[str, int] = {}
        by_frequency: dict[str, int] = {}
        for r in self._records:
            by_surface[r.risk_surface.value] = by_surface.get(r.risk_surface.value, 0) + 1
            by_exposure[r.exposure_type.value] = by_exposure.get(r.exposure_type.value, 0) + 1
            by_frequency[r.monitoring_frequency.value] = (
                by_frequency.get(r.monitoring_frequency.value, 0) + 1
            )
        high_risk_count = sum(1 for r in self._records if r.risk_score >= self._risk_threshold)
        scores = [r.risk_score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        top = [
            r.risk_name
            for r in sorted(
                self._records,
                key=lambda x: x.risk_score,
                reverse=True,
            )[:5]
        ]
        recs: list[str] = []
        if high_risk_count > 0:
            recs.append(f"{high_risk_count} high-risk digital exposure(s) detected")
        if not recs:
            recs.append("Digital risk exposure is within limits")
        return RiskReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            high_risk_count=high_risk_count,
            avg_risk_score=avg,
            by_surface=by_surface,
            by_exposure=by_exposure,
            by_frequency=by_frequency,
            top_risks=top,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("digital_risk_monitor.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        surface_dist: dict[str, int] = {}
        for r in self._records:
            key = r.risk_surface.value
            surface_dist[key] = surface_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "risk_threshold": self._risk_threshold,
            "surface_distribution": surface_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
