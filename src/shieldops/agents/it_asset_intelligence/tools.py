"""IT Asset Intelligence Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    AssetCategory,
    AssetRiskReport,
    CriticalityClassification,
    ITAsset,
    RiskPosture,
    SecurityPosture,
    ThreatCorrelation,
)

logger = structlog.get_logger()

_ASSET_PROFILES: dict[str, list[dict[str, Any]]] = {
    "servers": [
        {
            "category": AssetCategory.SERVER,
            "os": "Ubuntu 22.04",
            "managed": True,
        },
        {
            "category": AssetCategory.SERVER,
            "os": "RHEL 9.2",
            "managed": True,
        },
    ],
    "endpoints": [
        {
            "category": AssetCategory.ENDPOINT,
            "os": "Windows 11",
            "managed": True,
        },
        {
            "category": AssetCategory.ENDPOINT,
            "os": "macOS 14",
            "managed": True,
        },
    ],
    "cloud": [
        {
            "category": AssetCategory.CLOUD_RESOURCE,
            "os": "AWS EC2",
            "managed": True,
        },
        {
            "category": AssetCategory.CLOUD_RESOURCE,
            "os": "GCP GCE",
            "managed": False,
        },
    ],
    "ai_systems": [
        {
            "category": AssetCategory.AI_SYSTEM,
            "os": "LLM Runtime v2",
            "managed": False,
        },
    ],
    "network": [
        {
            "category": AssetCategory.NETWORK_DEVICE,
            "os": "Cisco IOS-XE 17",
            "managed": True,
        },
    ],
    "iot": [
        {
            "category": AssetCategory.IOT_DEVICE,
            "os": "Embedded Linux",
            "managed": False,
        },
    ],
}

_MITRE_TECHNIQUES = [
    "T1078",
    "T1190",
    "T1133",
    "T1059",
    "T1021",
    "T1071",
    "T1105",
    "T1027",
]


def _asset_id(tenant: str, name: str, idx: int) -> str:
    raw = f"{tenant}:{name}:{idx}"
    return f"ASSET-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


def _posture_from_score(score: float) -> RiskPosture:
    if score >= 8.0:
        return RiskPosture.CRITICAL
    if score >= 6.0:
        return RiskPosture.HIGH
    if score >= 4.0:
        return RiskPosture.MEDIUM
    if score >= 2.0:
        return RiskPosture.LOW
    return RiskPosture.COMPLIANT


class ITAssetIntelligenceToolkit:
    """Tools for IT asset discovery and risk assessment."""

    def __init__(
        self,
        cmdb_client: Any | None = None,
        threat_intel: Any | None = None,
        vuln_scanner: Any | None = None,
    ) -> None:
        self._cmdb = cmdb_client
        self._threat_intel = threat_intel
        self._vuln_scanner = vuln_scanner

    async def discover_assets(self, tenant_id: str) -> list[ITAsset]:
        """Discover IT assets for the tenant."""
        logger.info(
            "it_asset_intel.discover",
            tenant_id=tenant_id,
        )

        if self._cmdb is not None:
            try:
                raw = await self._cmdb.list_assets(tenant_id=tenant_id)
                return [ITAsset(**a) for a in raw]
            except Exception:
                logger.exception("it_asset_intel.discover.error")

        assets: list[ITAsset] = []
        idx = 0
        for group, profiles in _ASSET_PROFILES.items():
            for prof in profiles:
                aid = _asset_id(tenant_id, group, idx)
                assets.append(
                    ITAsset(
                        id=aid,
                        name=f"{group}-{idx:03d}",
                        category=prof["category"],
                        owner=f"team-{group}",
                        location="us-east-1",
                        os_version=prof["os"],
                        last_seen="2026-03-25T10:00:00Z",
                        managed=prof["managed"],
                        tags=[group],
                    )
                )
                idx += 1
        return assets

    async def classify_criticality(self, assets: list[ITAsset]) -> list[CriticalityClassification]:
        """Classify asset criticality."""
        logger.info(
            "it_asset_intel.classify",
            count=len(assets),
        )
        results: list[CriticalityClassification] = []
        for asset in assets:
            score = random.uniform(1.0, 9.5)  # noqa: S311
            tier = "tier-1" if score >= 7.0 else "tier-2" if score >= 4.0 else "tier-3"
            results.append(
                CriticalityClassification(
                    asset_id=asset.id,
                    business_impact=("high" if score >= 7.0 else "medium"),
                    data_sensitivity=(
                        "pii"
                        if asset.category
                        in (
                            AssetCategory.SERVER,
                            AssetCategory.CLOUD_RESOURCE,
                        )
                        else "internal"
                    ),
                    criticality_score=round(score, 1),
                    dependencies=[
                        f"dep-{random.randint(1, 50):03d}"  # noqa: S311
                    ],
                    tier=tier,
                )
            )
        return results

    async def assess_security_posture(self, assets: list[ITAsset]) -> list[SecurityPosture]:
        """Assess security posture for each asset."""
        logger.info(
            "it_asset_intel.posture",
            count=len(assets),
        )

        if self._vuln_scanner is not None:
            try:
                raw = await self._vuln_scanner.scan([a.id for a in assets])
                return [SecurityPosture(**r) for r in raw]
            except Exception:
                logger.exception("it_asset_intel.posture.error")

        results: list[SecurityPosture] = []
        for asset in assets:
            vulns = random.randint(0, 25)  # noqa: S311
            patch = round(
                random.uniform(60.0, 100.0),  # noqa: S311
                1,
            )
            score = vulns * 0.4 + (100 - patch) * 0.1
            results.append(
                SecurityPosture(
                    asset_id=asset.id,
                    vulnerability_count=vulns,
                    patch_compliance_pct=patch,
                    encryption_enabled=random.choice(  # noqa: S311
                        [True, True, False]
                    ),
                    edr_installed=asset.managed,
                    posture=_posture_from_score(score),
                    findings=[
                        f"CVE-2026-{random.randint(1000, 9999)}"  # noqa: S311
                        for _ in range(min(vulns, 3))
                    ],
                )
            )
        return results

    async def correlate_threats(
        self,
        assets: list[ITAsset],
        postures: list[SecurityPosture],
    ) -> list[ThreatCorrelation]:
        """Correlate assets with threat intelligence."""
        logger.info(
            "it_asset_intel.correlate",
            count=len(assets),
        )

        if self._threat_intel is not None:
            try:
                raw = await self._threat_intel.correlate([a.id for a in assets])
                return [ThreatCorrelation(**r) for r in raw]
            except Exception:
                logger.exception("it_asset_intel.correlate.error")

        posture_map = {p.asset_id: p for p in postures}
        results: list[ThreatCorrelation] = []
        for asset in assets:
            posture_map.get(asset.id)
            active = random.randint(0, 3)  # noqa: S311
            surface = round(
                random.uniform(1.0, 9.0),  # noqa: S311
                1,
            )
            techniques = random.sample(  # noqa: S311
                _MITRE_TECHNIQUES,
                k=min(active + 1, len(_MITRE_TECHNIQUES)),
            )
            results.append(
                ThreatCorrelation(
                    asset_id=asset.id,
                    threat_indicators=[
                        f"IOC-{random.randint(100, 999)}"  # noqa: S311
                        for _ in range(active)
                    ],
                    attack_surface_score=surface,
                    active_threats=active,
                    exposure_vector=("internet-facing" if not asset.managed else "internal"),
                    mitre_techniques=techniques,
                )
            )
        return results

    async def generate_risk_reports(
        self,
        assets: list[ITAsset],
        classifications: list[CriticalityClassification],
        postures: list[SecurityPosture],
        correlations: list[ThreatCorrelation],
    ) -> list[AssetRiskReport]:
        """Generate composite risk reports per asset."""
        logger.info(
            "it_asset_intel.risk_reports",
            count=len(assets),
        )
        class_map = {c.asset_id: c for c in classifications}
        posture_map = {p.asset_id: p for p in postures}
        corr_map = {c.asset_id: c for c in correlations}

        reports: list[AssetRiskReport] = []
        for asset in assets:
            cl = class_map.get(asset.id)
            po = posture_map.get(asset.id)
            co = corr_map.get(asset.id)

            crit = cl.criticality_score if cl else 5.0
            threat = co.attack_surface_score if co else 3.0
            composite = round((crit * 0.4 + threat * 0.6), 1)

            recs: list[str] = []
            if po and po.vulnerability_count > 10:
                recs.append("Patch critical vulnerabilities")
            if po and not po.edr_installed:
                recs.append("Install EDR agent")
            if po and not po.encryption_enabled:
                recs.append("Enable disk encryption")
            if co and co.active_threats > 0:
                recs.append("Investigate active threat indicators")

            reports.append(
                AssetRiskReport(
                    asset_id=asset.id,
                    asset_name=asset.name,
                    category=asset.category,
                    criticality_score=crit,
                    posture=(po.posture if po else RiskPosture.MEDIUM),
                    threat_score=threat,
                    composite_risk=composite,
                    recommendations=recs,
                )
            )
        return reports
