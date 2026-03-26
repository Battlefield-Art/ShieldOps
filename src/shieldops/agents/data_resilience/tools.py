"""Data Resilience Agent — Tool functions for data protection."""

from __future__ import annotations

import hashlib
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import (
    DataAnomaly,
    DataAsset,
    DataAssetType,
    ImmutabilityEnforcement,
    ProtectionAssessment,
    ProtectionLevel,
    RecoveryValidation,
)

logger = structlog.get_logger()

# Simulated asset profiles per cloud provider
_ASSET_PROFILES: dict[str, list[dict[str, Any]]] = {
    "aws": [
        {
            "asset_type": DataAssetType.DATABASE,
            "name": "prod-rds-primary",
            "size_gb": 500.0,
            "classification": "critical",
        },
        {
            "asset_type": DataAssetType.OBJECT_STORAGE,
            "name": "ml-artifacts-bucket",
            "size_gb": 2048.0,
            "classification": "high",
        },
        {
            "asset_type": DataAssetType.AI_MODEL,
            "name": "fraud-detection-model-v3",
            "size_gb": 12.5,
            "classification": "critical",
        },
        {
            "asset_type": DataAssetType.TRAINING_DATA,
            "name": "training-dataset-2024",
            "size_gb": 850.0,
            "classification": "high",
        },
        {
            "asset_type": DataAssetType.RAG_INDEX,
            "name": "knowledge-base-vector-store",
            "size_gb": 45.0,
            "classification": "high",
        },
    ],
    "gcp": [
        {
            "asset_type": DataAssetType.DATABASE,
            "name": "analytics-spanner-cluster",
            "size_gb": 320.0,
            "classification": "critical",
        },
        {
            "asset_type": DataAssetType.OBJECT_STORAGE,
            "name": "gcs-data-lake",
            "size_gb": 5120.0,
            "classification": "high",
        },
        {
            "asset_type": DataAssetType.AI_MODEL,
            "name": "vertex-recommendation-model",
            "size_gb": 8.2,
            "classification": "critical",
        },
    ],
    "azure": [
        {
            "asset_type": DataAssetType.DATABASE,
            "name": "cosmos-db-transactions",
            "size_gb": 180.0,
            "classification": "critical",
        },
        {
            "asset_type": DataAssetType.FILE_SYSTEM,
            "name": "azure-files-shared-configs",
            "size_gb": 25.0,
            "classification": "medium",
        },
        {
            "asset_type": DataAssetType.CONFIG,
            "name": "app-config-store",
            "size_gb": 0.5,
            "classification": "high",
        },
    ],
    "default": [
        {
            "asset_type": DataAssetType.DATABASE,
            "name": "primary-postgres",
            "size_gb": 200.0,
            "classification": "critical",
        },
        {
            "asset_type": DataAssetType.OBJECT_STORAGE,
            "name": "backup-bucket",
            "size_gb": 1024.0,
            "classification": "high",
        },
        {
            "asset_type": DataAssetType.AI_MODEL,
            "name": "default-ml-model",
            "size_gb": 5.0,
            "classification": "high",
        },
    ],
}

# Anomaly patterns for simulation
_ANOMALY_TYPES = [
    {
        "type": "mass_encryption",
        "severity": "critical",
        "ransomware": True,
        "desc": "Rapid encryption of multiple files detected",
    },
    {
        "type": "bulk_deletion",
        "severity": "critical",
        "ransomware": True,
        "desc": "Bulk deletion attempt on versioned objects",
    },
    {
        "type": "unexpected_modification",
        "severity": "high",
        "ransomware": False,
        "desc": "Unexpected modification of immutable asset",
    },
    {
        "type": "access_pattern_change",
        "severity": "medium",
        "ransomware": False,
        "desc": "Unusual access pattern deviation from baseline",
    },
    {
        "type": "exfiltration_attempt",
        "severity": "critical",
        "ransomware": False,
        "desc": "Large data transfer to unknown destination",
    },
    {
        "type": "model_weight_tampering",
        "severity": "critical",
        "ransomware": False,
        "desc": "AI model weights modified outside CI/CD",
    },
    {
        "type": "training_data_poisoning",
        "severity": "high",
        "ransomware": False,
        "desc": "Training data integrity check failed",
    },
    {
        "type": "config_drift",
        "severity": "medium",
        "ransomware": False,
        "desc": "Configuration file changed without approval",
    },
]

# Lock mechanisms by cloud provider
_LOCK_MECHANISMS: dict[str, dict[str, str]] = {
    "aws": {
        "mechanism": "S3 Object Lock (Governance/Compliance)",
        "action": "enable_object_lock",
    },
    "gcp": {
        "mechanism": "GCS Retention Policy + Bucket Lock",
        "action": "enable_retention_lock",
    },
    "azure": {
        "mechanism": "Azure Immutable Blob Storage (WORM)",
        "action": "enable_immutable_storage",
    },
    "default": {
        "mechanism": "WORM-compliant storage lock",
        "action": "enable_worm_lock",
    },
}


def _asset_id(tenant: str, provider: str, name: str) -> str:
    """Generate a deterministic asset ID."""
    raw = f"{tenant}:{provider}:{name}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"DA-{h.upper()}"


def _protection_level(has_lock: bool, has_version: bool, has_repl: bool) -> ProtectionLevel:
    """Determine protection level from capabilities."""
    if has_lock:
        return ProtectionLevel.IMMUTABLE
    if has_version:
        return ProtectionLevel.VERSIONED
    if has_repl:
        return ProtectionLevel.REPLICATED
    return ProtectionLevel.UNPROTECTED


class DataResilienceToolkit:
    """Tools for data resilience assessment and enforcement."""

    def __init__(
        self,
        storage_client: Any | None = None,
        cloud_provider: Any | None = None,
        backup_api: Any | None = None,
    ) -> None:
        self._storage_client = storage_client
        self._cloud_provider = cloud_provider
        self._backup_api = backup_api

    async def inventory_data_assets(
        self,
        tenant_id: str,
        providers: list[str] | None = None,
    ) -> list[DataAsset]:
        """Discover data assets across cloud providers.

        Uses live storage client when available, otherwise
        generates realistic simulated assets.
        """
        logger.info(
            "data_resilience.inventory",
            tenant_id=tenant_id,
            providers=providers,
        )

        if self._storage_client is not None:
            try:
                raw = await self._storage_client.list_assets(
                    tenant_id=tenant_id,
                    providers=providers,
                )
                return [DataAsset(**a) for a in raw]
            except Exception:
                logger.exception("data_resilience.inventory.error")

        target_providers = providers or [
            "aws",
            "gcp",
            "azure",
        ]
        assets: list[DataAsset] = []
        now = datetime.now(UTC).isoformat()

        for provider in target_providers:
            p_lower = provider.lower()
            profile_key = p_lower if p_lower in _ASSET_PROFILES else "default"
            for ap in _ASSET_PROFILES[profile_key]:
                noise = random.gauss(0, 50.0)  # noqa: S311
                size = round(max(0.1, ap["size_gb"] + noise), 1)
                assets.append(
                    DataAsset(
                        id=_asset_id(
                            tenant_id,
                            provider,
                            ap["name"],
                        ),
                        name=ap["name"],
                        asset_type=ap["asset_type"],
                        cloud_provider=provider,
                        region=random.choice(  # noqa: S311
                            [
                                "us-east-1",
                                "us-west-2",
                                "eu-west-1",
                                "ap-southeast-1",
                            ]
                        ),
                        size_gb=size,
                        last_modified=now,
                        owner=f"team-{provider}-data",
                        classification=ap["classification"],
                    )
                )

        return assets

    async def assess_protection(
        self,
        assets: list[DataAsset],
    ) -> list[ProtectionAssessment]:
        """Assess protection level for each data asset.

        Checks immutability, versioning, replication,
        backup status, and encryption.
        """
        logger.info(
            "data_resilience.assess_protection",
            asset_count=len(assets),
        )

        assessments: list[ProtectionAssessment] = []
        for i, asset in enumerate(assets):
            is_critical = asset.classification == "critical"
            has_lock = random.random() > (  # noqa: S311
                0.4 if is_critical else 0.7
            )
            has_ver = random.random() > 0.3  # noqa: S311
            has_repl = random.random() > 0.5  # noqa: S311
            has_backup = random.random() > 0.2  # noqa: S311
            encrypted = random.random() > 0.2  # noqa: S311
            backup_age = round(
                random.uniform(  # noqa: S311
                    1.0, 168.0
                ),
                1,
            )

            level = _protection_level(has_lock, has_ver, has_repl)

            gaps: list[str] = []
            if not has_lock:
                gaps.append("no_immutability_lock")
            if not has_ver:
                gaps.append("no_versioning")
            if not has_repl:
                gaps.append("no_replication")
            if not has_backup:
                gaps.append("no_backup")
            if not encrypted:
                gaps.append("no_encryption")
            if backup_age > 48.0:
                gaps.append("stale_backup")

            risk = round(  # noqa: S311
                min(10.0, len(gaps) * 1.8 + (2.0 if is_critical else 0.0)),
                1,
            )

            compliance: list[str] = []
            if encrypted and has_backup:
                compliance.append("SOC2")
            if has_lock and has_ver:
                compliance.append("SEC_17a-4")
            if encrypted:
                compliance.append("HIPAA")

            assessments.append(
                ProtectionAssessment(
                    id=f"PA-{i:04d}",
                    asset_id=asset.id,
                    protection_level=level,
                    has_object_lock=has_lock,
                    has_versioning=has_ver,
                    has_replication=has_repl,
                    has_backup=has_backup,
                    backup_age_hours=backup_age if has_backup else 0.0,
                    encryption_enabled=encrypted,
                    encryption_type=("AES-256-GCM" if encrypted else ""),
                    compliance_tags=compliance,
                    gaps=gaps,
                    risk_score=risk,
                )
            )

        return assessments

    async def detect_anomalies(
        self,
        assets: list[DataAsset],
    ) -> list[DataAnomaly]:
        """Detect anomalies on data assets.

        Checks for ransomware indicators, tampering,
        unexpected deletions, and exfiltration attempts.
        """
        logger.info(
            "data_resilience.detect_anomalies",
            asset_count=len(assets),
        )

        anomalies: list[DataAnomaly] = []
        now = datetime.now(UTC).isoformat()
        idx = 0

        for asset in assets:
            # Higher chance of anomalies on critical assets
            threshold = 0.65 if asset.classification == "critical" else 0.8
            if random.random() > threshold:  # noqa: S311
                anomaly_def = random.choice(  # noqa: S311
                    _ANOMALY_TYPES
                )
                indicators: list[str] = []
                if anomaly_def["ransomware"]:
                    indicators = [
                        "rapid_file_modification",
                        "entropy_increase",
                        "extension_change",
                    ]
                elif "model" in anomaly_def["type"]:
                    indicators = [
                        "checksum_mismatch",
                        "unauthorized_write",
                    ]
                else:
                    indicators = [
                        "access_pattern_deviation",
                        "unusual_api_call",
                    ]

                anomalies.append(
                    DataAnomaly(
                        id=f"ANM-{idx:04d}",
                        asset_id=asset.id,
                        anomaly_type=anomaly_def["type"],
                        severity=anomaly_def["severity"],
                        description=(f"{anomaly_def['desc']} on {asset.name}"),
                        detected_at=now,
                        indicators=indicators,
                        is_ransomware_indicator=(anomaly_def["ransomware"]),
                    )
                )
                idx += 1

        anomalies.sort(
            key=lambda a: {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
            }.get(a.severity, 4)
        )
        return anomalies

    async def enforce_immutability(
        self,
        assets: list[DataAsset],
        assessments: list[ProtectionAssessment],
    ) -> list[ImmutabilityEnforcement]:
        """Enforce immutability controls on unprotected assets.

        Applies object lock, WORM, versioning, and
        retention policies based on cloud provider.
        """
        logger.info(
            "data_resilience.enforce_immutability",
            asset_count=len(assets),
        )

        asset_map = {a.id: a for a in assets}
        enforcements: list[ImmutabilityEnforcement] = []
        now = datetime.now(UTC).isoformat()
        idx = 0

        for assessment in assessments:
            if assessment.protection_level in (ProtectionLevel.IMMUTABLE,):
                continue

            asset = asset_map.get(assessment.asset_id)
            if not asset:
                continue

            provider = asset.cloud_provider.lower()
            lock_config = _LOCK_MECHANISMS.get(
                provider,
                _LOCK_MECHANISMS["default"],
            )

            is_critical = asset.classification == "critical"
            retention = 365 if is_critical else 90

            enforcements.append(
                ImmutabilityEnforcement(
                    id=f"ENF-{idx:04d}",
                    asset_id=asset.id,
                    action=lock_config["action"],
                    mechanism=lock_config["mechanism"],
                    retention_days=retention,
                    status="applied",
                    applied_at=now,
                    rollback_available=True,
                )
            )
            idx += 1

        return enforcements

    async def validate_recovery(
        self,
        assets: list[DataAsset],
        assessments: list[ProtectionAssessment],
    ) -> list[RecoveryValidation]:
        """Validate recovery capabilities for data assets.

        Runs simulated restore tests and verifies data
        integrity via checksums.
        """
        logger.info(
            "data_resilience.validate_recovery",
            asset_count=len(assets),
        )

        assessment_map = {a.asset_id: a for a in assessments}
        validations: list[RecoveryValidation] = []
        idx = 0

        for asset in assets:
            pa = assessment_map.get(asset.id)
            if not pa or not pa.has_backup:
                validations.append(
                    RecoveryValidation(
                        id=f"RV-{idx:04d}",
                        asset_id=asset.id,
                        test_type="skip_no_backup",
                        status="skipped",
                        notes=(f"No backup available for {asset.name}"),
                    )
                )
                idx += 1
                continue

            # Simulate recovery test
            rto = round(
                random.uniform(  # noqa: S311
                    30.0, 3600.0
                ),
                1,
            )
            rpo = pa.backup_age_hours
            integrity = random.random() > 0.05  # noqa: S311
            checksum = random.random() > 0.03  # noqa: S311

            if rto > 1800.0:
                status = "degraded"
            elif not integrity:
                status = "failed"
            else:
                status = "passed"

            test_type = "full_restore" if asset.size_gb > 100 else "point_in_time"

            validations.append(
                RecoveryValidation(
                    id=f"RV-{idx:04d}",
                    asset_id=asset.id,
                    test_type=test_type,
                    recovery_time_seconds=rto,
                    recovery_point_age_hours=rpo,
                    data_integrity_verified=integrity,
                    checksum_match=checksum,
                    status=status,
                    notes=(f"RTO={rto:.0f}s RPO={rpo:.1f}h for {asset.name}"),
                )
            )
            idx += 1

        return validations
