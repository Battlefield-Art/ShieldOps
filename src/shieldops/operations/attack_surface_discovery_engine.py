"""AttackSurfaceDiscoveryEngine — Discover external attack surface via DNS, ports, and certs."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DiscoveryMethod(StrEnum):
    DNS_ENUM = "dns_enum"
    PORT_SCAN = "port_scan"
    CERT_TRANSPARENCY = "cert_transparency"
    API_DISCOVERY = "api_discovery"


class AssetType(StrEnum):
    WEB_APP = "web_app"
    API = "api"
    DNS = "dns"
    CERTIFICATE = "certificate"
    CLOUD_RESOURCE = "cloud_resource"


class ExposureStatus(StrEnum):
    EXPOSED = "exposed"
    PARTIALLY_EXPOSED = "partially_exposed"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


# --- Models ---


class DiscoveryRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    discovery_method: DiscoveryMethod = DiscoveryMethod.DNS_ENUM
    asset_type: AssetType = AssetType.WEB_APP
    exposure_status: ExposureStatus = ExposureStatus.UNKNOWN
    score: float = 0.0
    hostname: str = ""
    port: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class DiscoveryAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    discovery_method: DiscoveryMethod = DiscoveryMethod.DNS_ENUM
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DiscoveryReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_discovery_method: dict[str, int] = Field(default_factory=dict)
    by_asset_type: dict[str, int] = Field(default_factory=dict)
    by_exposure_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AttackSurfaceDiscoveryEngine:
    """Discover external attack surface via DNS, ports, and certs."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[DiscoveryRecord] = []
        self._analyses: list[DiscoveryAnalysis] = []
        logger.info(
            "attack_surface_discovery_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        name: str,
        discovery_method: DiscoveryMethod = DiscoveryMethod.DNS_ENUM,
        asset_type: AssetType = AssetType.WEB_APP,
        exposure_status: ExposureStatus = ExposureStatus.UNKNOWN,
        score: float = 0.0,
        hostname: str = "",
        port: int = 0,
        service: str = "",
        team: str = "",
    ) -> DiscoveryRecord:
        record = DiscoveryRecord(
            name=name,
            discovery_method=discovery_method,
            asset_type=asset_type,
            exposure_status=exposure_status,
            score=score,
            hostname=hostname,
            port=port,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "attack_surface_discovery_engine.record_added",
            record_id=record.id,
            name=name,
            discovery_method=discovery_method.value,
            asset_type=asset_type.value,
        )
        return record

    def get_record(self, record_id: str) -> DiscoveryRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        discovery_method: DiscoveryMethod | None = None,
        asset_type: AssetType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[DiscoveryRecord]:
        results = list(self._records)
        if discovery_method is not None:
            results = [r for r in results if r.discovery_method == discovery_method]
        if asset_type is not None:
            results = [r for r in results if r.asset_type == asset_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        discovery_method: DiscoveryMethod = DiscoveryMethod.DNS_ENUM,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> DiscoveryAnalysis:
        analysis = DiscoveryAnalysis(
            name=name,
            discovery_method=discovery_method,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "attack_surface_discovery_engine.analysis_added",
            name=name,
            discovery_method=discovery_method.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations -------------------------------------

    def discover_external_assets(self) -> list[dict[str, Any]]:
        """Discover externally exposed assets."""
        external: list[dict[str, Any]] = []
        for r in self._records:
            if r.exposure_status in (
                ExposureStatus.EXPOSED,
                ExposureStatus.PARTIALLY_EXPOSED,
            ):
                external.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "asset_type": r.asset_type.value,
                        "exposure_status": r.exposure_status.value,
                        "discovery_method": r.discovery_method.value,
                        "hostname": r.hostname,
                        "port": r.port,
                        "service": r.service,
                        "risk": (
                            "high" if r.exposure_status == ExposureStatus.EXPOSED else "medium"
                        ),
                    }
                )
        return sorted(
            external,
            key=lambda x: 0 if x["risk"] == "high" else 1,
        )

    def enumerate_shadow_it(self) -> list[dict[str, Any]]:
        """Enumerate shadow IT — assets with no team owner."""
        shadow: list[dict[str, Any]] = []
        for r in self._records:
            if not r.team or r.team == "unknown":
                shadow.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "asset_type": r.asset_type.value,
                        "exposure_status": r.exposure_status.value,
                        "hostname": r.hostname,
                        "port": r.port,
                        "service": r.service,
                        "risk": (
                            "high" if r.exposure_status == ExposureStatus.EXPOSED else "medium"
                        ),
                        "recommendation": "Assign ownership",
                    }
                )
        return sorted(
            shadow,
            key=lambda x: 0 if x["risk"] == "high" else 1,
        )

    def calculate_surface_area(self) -> dict[str, Any]:
        """Calculate total attack surface area."""
        total = len(self._records)
        exposed = sum(1 for r in self._records if r.exposure_status == ExposureStatus.EXPOSED)
        partial = sum(
            1 for r in self._records if r.exposure_status == ExposureStatus.PARTIALLY_EXPOSED
        )
        internal = sum(1 for r in self._records if r.exposure_status == ExposureStatus.INTERNAL)
        by_type: dict[str, int] = {}
        for r in self._records:
            by_type[r.asset_type.value] = by_type.get(r.asset_type.value, 0) + 1
        unique_hosts = len({r.hostname for r in self._records})
        unique_ports = len({r.port for r in self._records if r.port})
        exposure_ratio = round((exposed + partial) / total * 100, 2) if total else 0.0
        return {
            "total_assets": total,
            "exposed": exposed,
            "partially_exposed": partial,
            "internal": internal,
            "unique_hosts": unique_hosts,
            "unique_ports": unique_ports,
            "by_asset_type": by_type,
            "exposure_ratio_pct": exposure_ratio,
            "risk_level": (
                "critical"
                if exposure_ratio > 50
                else (
                    "high" if exposure_ratio > 30 else ("medium" if exposure_ratio > 10 else "low")
                )
            ),
        }

    # -- standard methods --------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.discovery_method.value
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
                        "discovery_method": r.discovery_method.value,
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

    # -- report / stats ----------------------------------------

    def generate_report(self) -> DiscoveryReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.discovery_method.value] = by_e1.get(r.discovery_method.value, 0) + 1
            by_e2[r.asset_type.value] = by_e2.get(r.asset_type.value, 0) + 1
            by_e3[r.exposure_status.value] = by_e3.get(r.exposure_status.value, 0) + 1
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
            recs.append("Attack Surface Discovery Engine is healthy")
        return DiscoveryReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_discovery_method=by_e1,
            by_asset_type=by_e2,
            by_exposure_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("attack_surface_discovery_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.discovery_method.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "discovery_method_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
