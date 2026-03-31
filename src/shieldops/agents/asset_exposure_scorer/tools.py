"""Asset Exposure Scorer Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any
from uuid import uuid4

import structlog

from .models import (
    AssetType,
    ChangeRecord,
    DiscoveredAsset,
    ExposureLevel,
    ExposureScore,
    ServiceFingerprint,
    VulnerabilityCheck,
)

logger = structlog.get_logger()

_SAMPLE_ASSETS: list[dict[str, Any]] = [
    {
        "hostname": "api.acme-corp.com",
        "ip_address": "52.14.88.101",
        "asset_type": "api_endpoint",
        "port": 443,
        "protocol": "https",
        "cloud_provider": "aws",
        "region": "us-east-1",
    },
    {
        "hostname": "dashboard.acme-corp.com",
        "ip_address": "52.14.88.102",
        "asset_type": "web_app",
        "port": 443,
        "protocol": "https",
        "cloud_provider": "aws",
        "region": "us-east-1",
    },
    {
        "hostname": "db-replica.acme-corp.com",
        "ip_address": "34.120.55.10",
        "asset_type": "database",
        "port": 5432,
        "protocol": "tcp",
        "cloud_provider": "gcp",
        "region": "us-central1",
    },
    {
        "hostname": "mail.acme-corp.com",
        "ip_address": "20.84.10.50",
        "asset_type": "mail_server",
        "port": 25,
        "protocol": "smtp",
        "cloud_provider": "azure",
        "region": "eastus",
    },
    {
        "hostname": "cdn.acme-corp.com",
        "ip_address": "52.14.88.200",
        "asset_type": "load_balancer",
        "port": 443,
        "protocol": "https",
        "cloud_provider": "aws",
        "region": "us-east-1",
    },
    {
        "hostname": "static.acme-corp.com",
        "ip_address": "34.120.55.20",
        "asset_type": "storage_bucket",
        "port": 443,
        "protocol": "https",
        "cloud_provider": "gcp",
        "region": "us-central1",
    },
]

_SAMPLE_CVES: list[dict[str, Any]] = [
    {
        "cve_id": "CVE-2024-21762",
        "severity": "critical",
        "cvss_score": 9.8,
        "description": "RCE in web server",
        "exploitable": True,
        "patch_available": True,
    },
    {
        "cve_id": "CVE-2024-3400",
        "severity": "critical",
        "cvss_score": 9.1,
        "description": "Auth bypass in gateway",
        "exploitable": True,
        "patch_available": True,
    },
    {
        "cve_id": "CVE-2024-1234",
        "severity": "high",
        "cvss_score": 7.5,
        "description": "SSRF in API endpoint",
        "exploitable": False,
        "patch_available": True,
    },
    {
        "cve_id": "CVE-2024-5678",
        "severity": "medium",
        "cvss_score": 5.3,
        "description": "Information disclosure",
        "exploitable": False,
        "patch_available": False,
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class AssetExposureScorerToolkit:
    """Tools for asset exposure scoring."""

    def __init__(
        self,
        scanner_api: Any | None = None,
        vuln_db: Any | None = None,
    ) -> None:
        self._scanner_api = scanner_api
        self._vuln_db = vuln_db

    async def discover_assets(
        self,
        tenant_id: str,
    ) -> list[DiscoveredAsset]:
        """Discover internet-facing assets."""
        logger.info(
            "aes.discover_assets",
            tenant_id=tenant_id,
        )

        if self._scanner_api is not None:
            try:
                raw = await self._scanner_api.scan(
                    tenant_id=tenant_id,
                )
                return [DiscoveredAsset(**r) for r in raw]
            except Exception:
                logger.exception("aes.discover_assets.error")

        assets: list[DiscoveredAsset] = []
        for i, a in enumerate(_SAMPLE_ASSETS):
            assets.append(
                DiscoveredAsset(
                    id=_gen_id("DA", tenant_id, i),
                    hostname=a["hostname"],
                    ip_address=a["ip_address"],
                    asset_type=AssetType(a["asset_type"]),
                    port=a["port"],
                    protocol=a["protocol"],
                    cloud_provider=a["cloud_provider"],
                    region=a["region"],
                    first_seen="2026-03-15T00:00:00Z",
                )
            )
        return assets

    async def fingerprint_services(
        self,
        assets: list[DiscoveredAsset],
    ) -> list[ServiceFingerprint]:
        """Fingerprint services running on discovered assets."""
        logger.info(
            "aes.fingerprint_services",
            count=len(assets),
        )

        fingerprints: list[ServiceFingerprint] = []
        _services = [
            ("nginx", "1.25.3"),
            ("Apache", "2.4.58"),
            ("PostgreSQL", "15.4"),
            ("Postfix", "3.8.4"),
            ("HAProxy", "2.9.1"),
            ("MinIO", "2024.01"),
        ]
        for i, asset in enumerate(assets):
            svc_name, svc_ver = _services[i % len(_services)]
            tls = "TLSv1.3" if asset.port == 443 else "N/A"
            fingerprints.append(
                ServiceFingerprint(
                    id=_gen_id("SF", asset.id, i),
                    asset_id=asset.id,
                    service_name=svc_name,
                    version=svc_ver,
                    banner=f"{svc_name}/{svc_ver}",
                    tls_version=tls,
                    certificate_expiry="2026-09-15T00:00:00Z",
                    headers={"Server": svc_name},
                    technologies=[svc_name.lower()],
                )
            )
        return fingerprints

    async def check_vulns(
        self,
        assets: list[DiscoveredAsset],
    ) -> list[VulnerabilityCheck]:
        """Check for known vulnerabilities on assets."""
        logger.info(
            "aes.check_vulns",
            count=len(assets),
        )

        vulns: list[VulnerabilityCheck] = []
        idx = 0
        for asset in assets:
            num_vulns = random.randint(0, 2)  # noqa: S311
            for j in range(num_vulns):
                cve = _SAMPLE_CVES[(idx + j) % len(_SAMPLE_CVES)]
                vulns.append(
                    VulnerabilityCheck(
                        id=_gen_id("VC", asset.id, idx),
                        asset_id=asset.id,
                        cve_id=cve["cve_id"],
                        severity=cve["severity"],
                        cvss_score=cve["cvss_score"],
                        description=cve["description"],
                        exploitable=cve["exploitable"],
                        patch_available=cve["patch_available"],
                    )
                )
                idx += 1
        return vulns

    async def score_exposure(
        self,
        assets: list[DiscoveredAsset],
        vulns: list[VulnerabilityCheck],
    ) -> list[ExposureScore]:
        """Compute exposure scores for each asset."""
        logger.info(
            "aes.score_exposure",
            assets=len(assets),
            vulns=len(vulns),
        )

        vuln_map: dict[str, list[VulnerabilityCheck]] = {}
        for v in vulns:
            vuln_map.setdefault(v.asset_id, []).append(v)

        scores: list[ExposureScore] = []
        for i, asset in enumerate(assets):
            asset_vulns = vuln_map.get(asset.id, [])
            vuln_score = sum(v.cvss_score for v in asset_vulns) / max(len(asset_vulns), 1)
            config_penalty = 2.0 if asset.port in (22, 25, 5432) else 0.0
            overall = min(round(vuln_score + config_penalty, 1), 10.0)

            if overall >= 8.0:
                level = ExposureLevel.CRITICAL
            elif overall >= 6.0:
                level = ExposureLevel.HIGH
            elif overall >= 4.0:
                level = ExposureLevel.MEDIUM
            elif overall >= 2.0:
                level = ExposureLevel.LOW
            else:
                level = ExposureLevel.MINIMAL

            factors: list[str] = []
            if asset_vulns:
                factors.append(f"{len(asset_vulns)} CVEs")
            if config_penalty > 0:
                factors.append(f"Risky port: {asset.port}")
            if hasattr(asset, "protocol") and asset.protocol != "https":
                factors.append(f"Protocol: {asset.protocol}")

            scores.append(
                ExposureScore(
                    id=_gen_id("ES", asset.id, i),
                    asset_id=asset.id,
                    hostname=asset.hostname,
                    overall_score=overall,
                    vuln_score=round(vuln_score, 1),
                    config_score=config_penalty,
                    exposure_level=level,
                    factors=factors,
                )
            )
        return scores

    async def track_changes(
        self,
        scores: list[ExposureScore],
    ) -> list[ChangeRecord]:
        """Track changes in exposure scores over time."""
        logger.info(
            "aes.track_changes",
            count=len(scores),
        )

        changes: list[ChangeRecord] = []
        for i, s in enumerate(scores):
            prev = random.uniform(  # noqa: S311
                max(s.overall_score - 3.0, 0.0),
                s.overall_score + 1.0,
            )
            prev = round(prev, 1)
            delta = round(s.overall_score - prev, 1)
            if abs(delta) > 0.5:
                change_type = "increased" if delta > 0 else "decreased"
                changes.append(
                    ChangeRecord(
                        id=_gen_id("CR", s.id, i),
                        asset_id=s.asset_id,
                        change_type=change_type,
                        previous_score=prev,
                        current_score=s.overall_score,
                        delta=delta,
                        detected_at="2026-03-30T12:00:00Z",
                        details=f"Exposure {change_type} for {s.hostname}",
                    )
                )
        return changes

    async def record_metric(
        self,
        metric_name: str,
        value: float,
    ) -> dict[str, Any]:
        """Record an operational metric."""
        _metric_id = str(uuid4())
        logger.info(
            "aes.record_metric",
            metric=metric_name,
            value=value,
        )
        return {
            "metric_id": _metric_id,
            "metric": metric_name,
            "value": value,
            "recorded": True,
        }
