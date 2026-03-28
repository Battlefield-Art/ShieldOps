"""Data Encryption Monitor Agent — Tool functions for encryption ops."""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from .models import (
    CertificateHealth,
    CertificateStatus,
    EncryptionAsset,
    EncryptionGap,
    EncryptionType,
    KeyRotationStatus,
)

logger = structlog.get_logger()

_WEAK_ALGORITHMS: set[str] = {
    "DES",
    "3DES",
    "RC4",
    "MD5",
    "SHA1",
    "TLS1.0",
    "TLS1.1",
    "SSLv3",
}

_COMPLIANCE_REQUIREMENTS: dict[str, dict[str, str]] = {
    "HIPAA": {
        "min_algorithm": "AES-256",
        "min_tls": "TLS1.2",
        "max_rotation_days": "365",
    },
    "PCI_DSS": {
        "min_algorithm": "AES-128",
        "min_tls": "TLS1.2",
        "max_rotation_days": "365",
    },
    "SOC2": {
        "min_algorithm": "AES-128",
        "min_tls": "TLS1.2",
        "max_rotation_days": "365",
    },
    "GDPR": {
        "min_algorithm": "AES-256",
        "min_tls": "TLS1.2",
        "max_rotation_days": "365",
    },
}


def _uid() -> str:
    return str(uuid.uuid4())[:12]


class DataEncryptionMonitorToolkit:
    """Tools for monitoring encryption posture across infra."""

    def __init__(
        self,
        aws_connector: Any | None = None,
        gcp_connector: Any | None = None,
        azure_connector: Any | None = None,
        vault_connector: Any | None = None,
        certificate_connector: Any | None = None,
    ) -> None:
        self._aws = aws_connector
        self._gcp = gcp_connector
        self._azure = azure_connector
        self._vault = vault_connector
        self._cert = certificate_connector
        self._asset_cache: dict[str, EncryptionAsset] = {}

    async def scan_assets(
        self,
        tenant_id: str,
        cloud_providers: list[str] | None = None,
        asset_types: list[str] | None = None,
    ) -> list[EncryptionAsset]:
        """Scan infrastructure for data stores and services.

        In production this queries AWS KMS/S3/RDS, GCP KMS,
        Azure Key Vault, and on-prem certificate stores.
        """
        logger.info(
            "encryption_monitor.scan_assets",
            tenant_id=tenant_id,
            providers=cloud_providers,
        )
        now = time.time()
        assets: list[EncryptionAsset] = []

        default_assets = [
            {
                "name": "prod-customer-db",
                "asset_type": "rds",
                "cloud_provider": "aws",
                "region": "us-east-1",
                "encryption_type": EncryptionType.AT_REST,
                "algorithm": "AES-256",
                "key_id": "aws-kms-key-001",
                "is_encrypted": True,
                "owner": "platform-team",
                "compliance_tags": ["HIPAA", "SOC2"],
            },
            {
                "name": "analytics-bucket",
                "asset_type": "s3",
                "cloud_provider": "aws",
                "region": "us-west-2",
                "encryption_type": EncryptionType.NONE,
                "algorithm": "",
                "key_id": "",
                "is_encrypted": False,
                "owner": "data-team",
                "compliance_tags": ["SOC2"],
            },
            {
                "name": "user-uploads-bucket",
                "asset_type": "s3",
                "cloud_provider": "aws",
                "region": "us-east-1",
                "encryption_type": EncryptionType.AT_REST,
                "algorithm": "AES-256",
                "key_id": "aws-kms-key-002",
                "is_encrypted": True,
                "owner": "product-team",
                "compliance_tags": ["GDPR", "SOC2"],
            },
            {
                "name": "legacy-payments-db",
                "asset_type": "rds",
                "cloud_provider": "aws",
                "region": "us-east-1",
                "encryption_type": EncryptionType.AT_REST,
                "algorithm": "3DES",
                "key_id": "aws-kms-key-003",
                "is_encrypted": True,
                "owner": "payments-team",
                "compliance_tags": ["PCI_DSS"],
            },
            {
                "name": "api-gateway",
                "asset_type": "service",
                "cloud_provider": "aws",
                "region": "us-east-1",
                "encryption_type": EncryptionType.IN_TRANSIT,
                "algorithm": "TLS1.3",
                "key_id": "",
                "is_encrypted": True,
                "owner": "platform-team",
                "compliance_tags": ["SOC2"],
            },
            {
                "name": "internal-service-mesh",
                "asset_type": "service",
                "cloud_provider": "gcp",
                "region": "us-central1",
                "encryption_type": EncryptionType.IN_TRANSIT,
                "algorithm": "TLS1.1",
                "key_id": "",
                "is_encrypted": True,
                "owner": "infra-team",
                "compliance_tags": ["SOC2"],
            },
            {
                "name": "ml-training-data",
                "asset_type": "gcs",
                "cloud_provider": "gcp",
                "region": "us-central1",
                "encryption_type": EncryptionType.NONE,
                "algorithm": "",
                "key_id": "",
                "is_encrypted": False,
                "owner": "ml-team",
                "compliance_tags": ["GDPR"],
            },
        ]

        providers = cloud_providers or [
            "aws",
            "gcp",
            "azure",
            "on_prem",
        ]
        types = asset_types or []

        for ad in default_assets:
            if ad["cloud_provider"] not in providers:
                continue
            if types and ad["asset_type"] not in types:
                continue
            asset = EncryptionAsset(
                id=_uid(),
                name=ad["name"],  # type: ignore[arg-type]
                asset_type=ad["asset_type"],  # type: ignore[arg-type]
                cloud_provider=ad["cloud_provider"],  # type: ignore[arg-type]
                region=ad["region"],  # type: ignore[arg-type]
                encryption_type=ad["encryption_type"],  # type: ignore[arg-type]
                algorithm=ad["algorithm"],  # type: ignore[arg-type]
                key_id=ad["key_id"],  # type: ignore[arg-type]
                is_encrypted=ad["is_encrypted"],  # type: ignore[arg-type]
                owner=ad["owner"],  # type: ignore[arg-type]
                last_assessed=now,
                compliance_tags=ad["compliance_tags"],  # type: ignore[arg-type]
            )
            assets.append(asset)
            self._asset_cache[asset.id] = asset

        return assets

    async def check_key_rotation(
        self,
        assets: list[EncryptionAsset],
    ) -> list[KeyRotationStatus]:
        """Check key rotation schedules for encrypted assets.

        In production calls AWS KMS DescribeKey, GCP KMS
        CryptoKeyVersions, and HashiCorp Vault key metadata.
        """
        logger.info(
            "encryption_monitor.check_key_rotation",
            asset_count=len(assets),
        )
        now = time.time()
        statuses: list[KeyRotationStatus] = []

        _key_data: dict[str, dict[str, Any]] = {
            "aws-kms-key-001": {
                "alias": "prod-customer-key",
                "provider": "aws_kms",
                "algorithm": "AES-256",
                "created_days_ago": 400,
                "last_rotated_days_ago": 95,
                "rotation_interval_days": 90,
                "auto_rotation": True,
                "usage_count": 12_500,
            },
            "aws-kms-key-002": {
                "alias": "user-uploads-key",
                "provider": "aws_kms",
                "algorithm": "AES-256",
                "created_days_ago": 200,
                "last_rotated_days_ago": 45,
                "rotation_interval_days": 90,
                "auto_rotation": True,
                "usage_count": 8_200,
            },
            "aws-kms-key-003": {
                "alias": "legacy-payments-key",
                "provider": "aws_kms",
                "algorithm": "3DES",
                "created_days_ago": 900,
                "last_rotated_days_ago": 450,
                "rotation_interval_days": 365,
                "auto_rotation": False,
                "usage_count": 3_100,
            },
        }

        seen_keys: set[str] = set()
        for asset in assets:
            if not asset.key_id or asset.key_id in seen_keys:
                continue
            seen_keys.add(asset.key_id)

            kd = _key_data.get(asset.key_id)
            if not kd:
                continue

            day_s = 86_400
            created = now - (kd["created_days_ago"] * day_s)
            last_rot = now - (kd["last_rotated_days_ago"] * day_s)
            interval = kd["rotation_interval_days"]
            next_rot = last_rot + (interval * day_s)
            days_until = int((next_rot - now) / day_s)
            is_overdue = days_until < 0

            statuses.append(
                KeyRotationStatus(
                    key_id=asset.key_id,
                    key_alias=kd["alias"],
                    provider=kd["provider"],
                    algorithm=kd["algorithm"],
                    created_at=created,
                    last_rotated=last_rot,
                    rotation_interval_days=interval,
                    next_rotation=next_rot,
                    is_overdue=is_overdue,
                    auto_rotation_enabled=kd["auto_rotation"],
                    days_until_rotation=days_until,
                    usage_count=kd["usage_count"],
                )
            )

        return statuses

    async def check_certificates(
        self,
        assets: list[EncryptionAsset],
    ) -> list[CertificateHealth]:
        """Check TLS/SSL certificate health for services.

        In production queries certificate transparency logs,
        AWS ACM, Let's Encrypt, and internal PKI.
        """
        logger.info(
            "encryption_monitor.check_certificates",
            asset_count=len(assets),
        )
        now = time.time()
        certs: list[CertificateHealth] = []
        day_s = 86_400

        _cert_data: list[dict[str, Any]] = [
            {
                "domain": "api.shieldops.io",
                "issuer": "Let's Encrypt",
                "key_size": 2048,
                "sig_algo": "SHA256withRSA",
                "days_until": 45,
                "status": CertificateStatus.VALID,
                "auto_renew": True,
                "san": ["api.shieldops.io", "*.api.shieldops.io"],
                "wildcard": True,
            },
            {
                "domain": "dashboard.shieldops.io",
                "issuer": "Let's Encrypt",
                "key_size": 2048,
                "sig_algo": "SHA256withRSA",
                "days_until": 12,
                "status": CertificateStatus.EXPIRING_SOON,
                "auto_renew": True,
                "san": ["dashboard.shieldops.io"],
                "wildcard": False,
            },
            {
                "domain": "internal.legacy.corp",
                "issuer": "Self-Signed",
                "key_size": 1024,
                "sig_algo": "SHA1withRSA",
                "days_until": -30,
                "status": CertificateStatus.EXPIRED,
                "auto_renew": False,
                "san": ["internal.legacy.corp"],
                "wildcard": False,
            },
            {
                "domain": "payments.corp.io",
                "issuer": "DigiCert",
                "key_size": 4096,
                "sig_algo": "SHA256withRSA",
                "days_until": 180,
                "status": CertificateStatus.VALID,
                "auto_renew": False,
                "san": ["payments.corp.io", "pay.corp.io"],
                "wildcard": False,
            },
        ]

        service_assets = [a for a in assets if a.encryption_type == EncryptionType.IN_TRANSIT]

        # Return certs regardless (cert monitoring is global)
        for cd in _cert_data:
            not_after = now + (cd["days_until"] * day_s)
            not_before = not_after - (365 * day_s)
            certs.append(
                CertificateHealth(
                    id=_uid(),
                    domain=cd["domain"],
                    issuer=cd["issuer"],
                    serial_number=_uid(),
                    status=cd["status"],
                    not_before=not_before,
                    not_after=not_after,
                    days_until_expiry=cd["days_until"],
                    key_size=cd["key_size"],
                    signature_algorithm=cd["sig_algo"],
                    san_domains=cd["san"],
                    is_wildcard=cd["wildcard"],
                    auto_renew=cd["auto_renew"],
                )
            )

        # Mark service-specific certs
        _ = service_assets  # used for future enrichment
        return certs

    async def identify_gaps(
        self,
        assets: list[EncryptionAsset],
        key_statuses: list[KeyRotationStatus],
        certificates: list[CertificateHealth],
    ) -> list[EncryptionGap]:
        """Identify encryption gaps and weaknesses.

        Cross-references assets, key rotation, and cert health
        to find unencrypted stores, weak algorithms, expired
        certs, and overdue key rotations.
        """
        logger.info(
            "encryption_monitor.identify_gaps",
            assets=len(assets),
            keys=len(key_statuses),
            certs=len(certificates),
        )
        gaps: list[EncryptionGap] = []

        # Gap: unencrypted assets
        for asset in assets:
            if not asset.is_encrypted:
                gaps.append(
                    EncryptionGap(
                        id=_uid(),
                        asset_id=asset.id,
                        gap_type="unencrypted",
                        severity="critical",
                        description=(f"{asset.name} ({asset.asset_type}) has no encryption"),
                        recommendation=(
                            f"Enable encryption for {asset.name} "
                            f"using AES-256 with customer-managed key"
                        ),
                        compliance_impact=asset.compliance_tags,
                    )
                )

        # Gap: weak algorithms
        for asset in assets:
            if asset.is_encrypted and asset.algorithm.upper() in _WEAK_ALGORITHMS:
                gaps.append(
                    EncryptionGap(
                        id=_uid(),
                        asset_id=asset.id,
                        gap_type="weak_algorithm",
                        severity="high",
                        description=(f"{asset.name} uses weak algorithm {asset.algorithm}"),
                        recommendation=(f"Upgrade {asset.name} from {asset.algorithm} to AES-256"),
                        compliance_impact=asset.compliance_tags,
                    )
                )

        # Gap: overdue key rotation
        for ks in key_statuses:
            if ks.is_overdue:
                gaps.append(
                    EncryptionGap(
                        id=_uid(),
                        asset_id=ks.key_id,
                        gap_type="overdue_rotation",
                        severity="high",
                        description=(
                            f"Key {ks.key_alias} is "
                            f"{abs(ks.days_until_rotation)}d overdue "
                            f"for rotation"
                        ),
                        recommendation=(
                            f"Rotate key {ks.key_alias} immediately and enable auto-rotation"
                        ),
                        compliance_impact=["PCI_DSS", "SOC2"],
                    )
                )

        # Gap: expired or expiring certificates
        for cert in certificates:
            if cert.status == CertificateStatus.EXPIRED:
                gaps.append(
                    EncryptionGap(
                        id=_uid(),
                        asset_id=cert.id,
                        gap_type="expired_cert",
                        severity="critical",
                        description=(
                            f"Certificate for {cert.domain} expired "
                            f"{abs(cert.days_until_expiry)}d ago"
                        ),
                        recommendation=(f"Renew certificate for {cert.domain} immediately"),
                        compliance_impact=["SOC2", "PCI_DSS"],
                    )
                )
            elif cert.status == CertificateStatus.EXPIRING_SOON:
                gaps.append(
                    EncryptionGap(
                        id=_uid(),
                        asset_id=cert.id,
                        gap_type="expiring_cert",
                        severity="medium",
                        description=(
                            f"Certificate for {cert.domain} expires in {cert.days_until_expiry}d"
                        ),
                        recommendation=(f"Renew certificate for {cert.domain} before expiry"),
                        compliance_impact=["SOC2"],
                    )
                )

        # Gap: weak certificate crypto
        for cert in certificates:
            if cert.key_size < 2048:
                gaps.append(
                    EncryptionGap(
                        id=_uid(),
                        asset_id=cert.id,
                        gap_type="weak_cert_crypto",
                        severity="high",
                        description=(
                            f"Certificate for {cert.domain} has "
                            f"{cert.key_size}-bit key (minimum 2048)"
                        ),
                        recommendation=(
                            f"Reissue {cert.domain} cert with 2048-bit or 4096-bit key"
                        ),
                        compliance_impact=["PCI_DSS", "SOC2"],
                    )
                )

        return gaps
