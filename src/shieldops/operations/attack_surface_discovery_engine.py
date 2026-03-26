"""Attack Surface Discovery — external attack surface."""

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
    DNS_ENUMERATION = "dns_enumeration"
    PORT_SCAN = "port_scan"
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    OSINT = "osint"
    CLOUD_API = "cloud_api"


class AssetType(StrEnum):
    WEB_APP = "web_app"
    API_ENDPOINT = "api_endpoint"
    DNS_RECORD = "dns_record"
    IP_ADDRESS = "ip_address"
    CLOUD_RESOURCE = "cloud_resource"


class ExposureStatus(StrEnum):
    EXPOSED = "exposed"
    PARTIALLY_EXPOSED = "partially_exposed"
    PROTECTED = "protected"
    UNKNOWN = "unknown"
    DECOMMISSIONED = "decommissioned"


# --- Models ---


class SurfaceDiscoveryRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    discovery_id: str = ""
    method: DiscoveryMethod = DiscoveryMethod.DNS_ENUMERATION
    asset_type: AssetType = AssetType.WEB_APP
    exposure: ExposureStatus = ExposureStatus.UNKNOWN
    asset_identifier: str = ""
    domain: str = ""
    open_ports: int = 0
    risk_score: float = 0.0
    is_shadow_it: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SurfaceDiscoveryAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    discovery_id: str = ""
    method: DiscoveryMethod = DiscoveryMethod.DNS_ENUMERATION
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SurfaceDiscoveryReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    exposed_count: int = 0
    shadow_it_count: int = 0
    by_method: dict[str, int] = Field(default_factory=dict)
    by_asset_type: dict[str, int] = Field(default_factory=dict)
    by_exposure: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AttackSurfaceDiscoveryEngine:
    """Discover external attack surface assets."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 0.6,
    ) -> None:
        self._max_records = max_records
        self._threshold = risk_threshold
        self._records: list[SurfaceDiscoveryRecord] = []
        self._analyses: list[SurfaceDiscoveryAnalysis] = []
        logger.info(
            "attack_surface_discovery.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        discovery_id: str,
        method: DiscoveryMethod = (DiscoveryMethod.DNS_ENUMERATION),
        asset_type: AssetType = AssetType.WEB_APP,
        exposure: ExposureStatus = (ExposureStatus.UNKNOWN),
        asset_identifier: str = "",
        domain: str = "",
        open_ports: int = 0,
        risk_score: float = 0.0,
        is_shadow_it: bool = False,
        service: str = "",
        team: str = "",
    ) -> SurfaceDiscoveryRecord:
        record = SurfaceDiscoveryRecord(
            discovery_id=discovery_id,
            method=method,
            asset_type=asset_type,
            exposure=exposure,
            asset_identifier=asset_identifier,
            domain=domain,
            open_ports=open_ports,
            risk_score=risk_score,
            is_shadow_it=is_shadow_it,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "attack_surface_discovery.record_added",
            record_id=record.id,
            discovery_id=discovery_id,
            asset_type=asset_type.value,
            exposure=exposure.value,
        )
        return record

    def get_record(self, record_id: str) -> SurfaceDiscoveryRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        asset_type: AssetType | None = None,
        exposure: ExposureStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[SurfaceDiscoveryRecord]:
        results = list(self._records)
        if asset_type is not None:
            results = [r for r in results if r.asset_type == asset_type]
        if exposure is not None:
            results = [r for r in results if r.exposure == exposure]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, discovery_id: str) -> SurfaceDiscoveryAnalysis:
        matched = [r for r in self._records if r.discovery_id == discovery_id]
        scores = [r.risk_score for r in matched]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        breached = avg > self._threshold
        analysis = SurfaceDiscoveryAnalysis(
            discovery_id=discovery_id,
            method=(matched[-1].method if matched else DiscoveryMethod.DNS_ENUMERATION),
            analysis_score=avg,
            threshold=self._threshold,
            breached=breached,
            description=(f"Risk {avg} for {discovery_id}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ------------------------------------

    def discover_external_assets(
        self,
        discovery_id: str,
        domain: str,
        method: DiscoveryMethod = (DiscoveryMethod.DNS_ENUMERATION),
    ) -> dict[str, Any]:
        """Discover external-facing assets."""
        record = self.add_record(
            discovery_id=discovery_id,
            domain=domain,
            method=method,
            exposure=ExposureStatus.EXPOSED,
        )
        analysis = self.process(discovery_id)
        return {
            "record_id": record.id,
            "discovery_id": discovery_id,
            "domain": domain,
            "method": method.value,
            "analysis_score": (analysis.analysis_score),
            "breached": analysis.breached,
        }

    def enumerate_shadow_it(
        self,
    ) -> list[dict[str, Any]]:
        """Enumerate shadow IT assets."""
        shadow = [r for r in self._records if r.is_shadow_it]
        results: list[dict[str, Any]] = []
        for r in shadow:
            results.append(
                {
                    "record_id": r.id,
                    "asset_identifier": (r.asset_identifier),
                    "asset_type": r.asset_type.value,
                    "domain": r.domain,
                    "exposure": r.exposure.value,
                    "risk_score": r.risk_score,
                }
            )
        results.sort(
            key=lambda x: x["risk_score"],
            reverse=True,
        )
        return results

    def calculate_surface_area(
        self,
    ) -> dict[str, Any]:
        """Calculate total attack surface area."""
        if not self._records:
            return {
                "total_assets": 0,
                "surface_score": 0.0,
            }
        exposed = sum(
            1
            for r in self._records
            if r.exposure
            in (
                ExposureStatus.EXPOSED,
                ExposureStatus.PARTIALLY_EXPOSED,
            )
        )
        total = len(self._records)
        exposure_rate = round(exposed / total * 100, 2)
        total_ports = sum(r.open_ports for r in self._records)
        shadow_ct = sum(1 for r in self._records if r.is_shadow_it)
        avg_risk = round(
            sum(r.risk_score for r in self._records) / total,
            4,
        )
        by_type: dict[str, int] = {}
        for r in self._records:
            key = r.asset_type.value
            by_type[key] = by_type.get(key, 0) + 1
        return {
            "total_assets": total,
            "exposed_assets": exposed,
            "exposure_rate_pct": exposure_rate,
            "total_open_ports": total_ports,
            "shadow_it_count": shadow_ct,
            "avg_risk_score": avg_risk,
            "surface_score": round(avg_risk * exposed, 2),
            "by_asset_type": by_type,
        }

    # -- report / stats ----------------------------------------

    def generate_report(
        self,
    ) -> SurfaceDiscoveryReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.method.value] = by_e1.get(r.method.value, 0) + 1
            by_e2[r.asset_type.value] = by_e2.get(r.asset_type.value, 0) + 1
            by_e3[r.exposure.value] = by_e3.get(r.exposure.value, 0) + 1
        exposed_ct = sum(1 for r in self._records if r.exposure == ExposureStatus.EXPOSED)
        shadow_ct = sum(1 for r in self._records if r.is_shadow_it)
        gap_count = sum(1 for r in self._records if r.risk_score > self._threshold)
        top_gaps = [r.discovery_id for r in self._records if r.risk_score > self._threshold][:5]
        recs: list[str] = []
        if exposed_ct > 0:
            recs.append(f"{exposed_ct} exposed asset(s)")
        if shadow_ct > 0:
            recs.append(f"{shadow_ct} shadow IT asset(s)")
        if not recs:
            recs.append("Attack Surface Discovery healthy")
        return SurfaceDiscoveryReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            exposed_count=exposed_ct,
            shadow_it_count=shadow_ct,
            by_method=by_e1,
            by_asset_type=by_e2,
            by_exposure=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("attack_surface_discovery.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.asset_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "asset_type_distribution": e1_dist,
            "unique_domains": len({r.domain for r in self._records}),
            "shadow_it_count": sum(1 for r in self._records if r.is_shadow_it),
        }
