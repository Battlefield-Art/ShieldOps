"""Asset Inventory Agent — Tool functions for asset lifecycle."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import (
    AssetType,
    ClassifiedAsset,
    Criticality,
    DiscoveredAsset,
    OwnerAssignment,
    ReconciliationResult,
    RiskAssessment,
)

logger = structlog.get_logger()

# Criticality scoring weights
_TYPE_CRITICALITY: dict[AssetType, Criticality] = {
    AssetType.DATABASE: Criticality.CRITICAL,
    AssetType.API_ENDPOINT: Criticality.HIGH,
    AssetType.AI_MODEL: Criticality.HIGH,
    AssetType.SERVICE_ACCOUNT: Criticality.HIGH,
    AssetType.SERVER: Criticality.MEDIUM,
    AssetType.CONTAINER: Criticality.MEDIUM,
    AssetType.STORAGE: Criticality.MEDIUM,
    AssetType.NETWORK: Criticality.LOW,
    AssetType.UNKNOWN: Criticality.INFORMATIONAL,
}

# Team mapping by asset type
_TEAM_MAP: dict[AssetType, str] = {
    AssetType.SERVER: "platform-eng",
    AssetType.CONTAINER: "platform-eng",
    AssetType.DATABASE: "data-eng",
    AssetType.API_ENDPOINT: "backend-eng",
    AssetType.STORAGE: "data-eng",
    AssetType.NETWORK: "network-ops",
    AssetType.AI_MODEL: "ml-eng",
    AssetType.SERVICE_ACCOUNT: "security-ops",
    AssetType.UNKNOWN: "security-ops",
}


def _generate_asset_id(name: str, provider: str) -> str:
    """Generate a deterministic asset ID."""
    raw = f"{name}:{provider}"
    return f"AST-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class AssetInventoryToolkit:
    """Tools for asset inventory lifecycle management."""

    def __init__(
        self,
        cloud_client: Any | None = None,
        cmdb_client: Any | None = None,
        scanner_client: Any | None = None,
    ) -> None:
        self._cloud_client = cloud_client
        self._cmdb_client = cmdb_client
        self._scanner_client = scanner_client

    async def discover_assets(self, tenant_id: str) -> list[DiscoveredAsset]:
        """Scan infrastructure for assets."""
        logger.info("asset_inventory.discover", tenant_id=tenant_id)

        if self._cloud_client is not None:
            try:
                raw = await self._cloud_client.list_assets(tenant_id=tenant_id)
                return [DiscoveredAsset(**a) for a in raw]
            except Exception:
                logger.exception("asset_inventory.discover.error")

        # Fallback: synthetic asset data
        now = datetime.now(UTC)
        return [
            DiscoveredAsset(
                id=_generate_asset_id("web-api-01", "aws"),
                name="web-api-01",
                asset_type=AssetType.API_ENDPOINT,
                cloud_provider="aws",
                region="us-east-1",
                ip_address="10.0.1.50",
                tags={"env": "prod", "team": "backend"},
                discovered_at=now,
                is_managed=True,
                source="aws-ec2",
            ),
            DiscoveredAsset(
                id=_generate_asset_id("postgres-primary", "aws"),
                name="postgres-primary",
                asset_type=AssetType.DATABASE,
                cloud_provider="aws",
                region="us-east-1",
                ip_address="10.0.2.10",
                tags={"env": "prod", "team": "data"},
                discovered_at=now,
                is_managed=True,
                source="aws-rds",
            ),
            DiscoveredAsset(
                id=_generate_asset_id("ml-inference-v2", "gcp"),
                name="ml-inference-v2",
                asset_type=AssetType.AI_MODEL,
                cloud_provider="gcp",
                region="us-central1",
                ip_address="",
                tags={"env": "prod", "team": "ml"},
                discovered_at=now,
                is_managed=True,
                source="gcp-vertex",
            ),
            DiscoveredAsset(
                id=_generate_asset_id("unknown-svc-8080", "aws"),
                name="unknown-svc-8080",
                asset_type=AssetType.UNKNOWN,
                cloud_provider="aws",
                region="us-west-2",
                ip_address="10.0.5.99",
                tags={},
                discovered_at=now,
                is_managed=False,
                source="network-scan",
            ),
            DiscoveredAsset(
                id=_generate_asset_id("k8s-worker-pool", "aws"),
                name="k8s-worker-pool",
                asset_type=AssetType.CONTAINER,
                cloud_provider="aws",
                region="us-east-1",
                ip_address="10.0.3.0/24",
                tags={"env": "prod", "team": "platform"},
                discovered_at=now,
                is_managed=True,
                source="aws-eks",
            ),
        ]

    async def classify_asset(self, asset: DiscoveredAsset) -> ClassifiedAsset:
        """Classify an asset by criticality and compliance scope."""
        logger.info(
            "asset_inventory.classify",
            asset_id=asset.id,
            asset_type=asset.asset_type,
        )

        criticality = _TYPE_CRITICALITY.get(asset.asset_type, Criticality.INFORMATIONAL)
        # Elevate criticality for production internet-facing assets
        is_internet = asset.tags.get("env") == "prod"
        if is_internet and criticality == Criticality.MEDIUM:
            criticality = Criticality.HIGH

        compliance: list[str] = []
        if asset.asset_type == AssetType.DATABASE:
            compliance = ["SOC2", "PCI-DSS", "HIPAA"]
        elif asset.asset_type == AssetType.API_ENDPOINT:
            compliance = ["SOC2", "PCI-DSS"]
        elif asset.asset_type == AssetType.AI_MODEL:
            compliance = ["SOC2", "NIST-AI-RMF"]

        sensitivity = (
            "high" if asset.asset_type in (AssetType.DATABASE, AssetType.AI_MODEL) else "standard"
        )

        return ClassifiedAsset(
            asset_id=asset.id,
            asset_type=asset.asset_type,
            criticality=criticality,
            data_sensitivity=sensitivity,
            internet_facing=is_internet,
            compliance_scope=compliance,
            classification_rationale=(
                f"{asset.asset_type.value} in {asset.cloud_provider}/{asset.region}"
            ),
        )

    async def assign_owner(self, asset: DiscoveredAsset) -> OwnerAssignment:
        """Assign ownership for a discovered asset."""
        logger.info("asset_inventory.assign_owner", asset_id=asset.id)

        team = asset.tags.get("team", "")
        if not team:
            team = _TEAM_MAP.get(asset.asset_type, "security-ops")

        confidence = 0.9 if asset.tags.get("team") else 0.5

        return OwnerAssignment(
            asset_id=asset.id,
            owner_team=team,
            owner_email=f"{team}@company.com",
            backup_owner=f"{team}-lead@company.com",
            assignment_method=("tag-based" if asset.tags.get("team") else "type-heuristic"),
            confidence=confidence,
        )

    async def assess_risk(
        self,
        asset: DiscoveredAsset,
        classification: ClassifiedAsset,
    ) -> RiskAssessment:
        """Assess risk for a classified asset."""
        logger.info("asset_inventory.assess_risk", asset_id=asset.id)

        score = 0.0
        if classification.criticality == Criticality.CRITICAL:
            score += 40
        elif classification.criticality == Criticality.HIGH:
            score += 25
        elif classification.criticality == Criticality.MEDIUM:
            score += 15

        if not asset.is_managed:
            score += 30
        if classification.internet_facing:
            score += 15
        if classification.data_sensitivity == "high":
            score += 10

        score = min(score, 100.0)

        recommendations: list[str] = []
        if not asset.is_managed:
            recommendations.append("Onboard asset to CMDB and assign owner")
        if score >= 50:
            recommendations.append("Schedule vulnerability scan within 24h")
        if classification.internet_facing:
            recommendations.append("Verify WAF and DDoS protection")

        return RiskAssessment(
            asset_id=asset.id,
            risk_score=score,
            vulnerabilities=0,
            misconfigurations=1 if not asset.is_managed else 0,
            exposure_level=("high" if score >= 50 else "medium" if score >= 25 else "low"),
            recommendations=recommendations,
        )

    async def reconcile_inventory(
        self,
        discovered: list[DiscoveredAsset],
    ) -> ReconciliationResult:
        """Reconcile discovered assets against known inventory."""
        logger.info(
            "asset_inventory.reconcile",
            discovered_count=len(discovered),
        )

        if self._cmdb_client is not None:
            try:
                known = await self._cmdb_client.list_assets()
                known_ids = {a["id"] for a in known}
                discovered_ids = {a.id for a in discovered}
                return ReconciliationResult(
                    new_assets=len(discovered_ids - known_ids),
                    removed_assets=len(known_ids - discovered_ids),
                    changed_assets=0,
                    unmanaged_assets=sum(1 for a in discovered if not a.is_managed),
                    stale_assets=0,
                )
            except Exception:
                logger.exception("asset_inventory.reconcile.error")

        unmanaged = sum(1 for a in discovered if not a.is_managed)
        return ReconciliationResult(
            new_assets=1,
            removed_assets=0,
            changed_assets=2,
            unmanaged_assets=unmanaged,
            stale_assets=0,
            drift_items=[
                "unknown-svc-8080: not in CMDB",
                "k8s-worker-pool: tag mismatch",
            ],
        )
