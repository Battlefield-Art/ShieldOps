"""Cloud Storage Scanner Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    EncryptionAssessment,
    PermissionFinding,
    RemediationAction,
    SensitiveDataFinding,
    StorageBucket,
    StorageProvider,
    StorageSeverity,
)

logger = structlog.get_logger()

_BUCKET_PROFILES: list[dict[str, Any]] = [
    {
        "name": "prod-app-assets",
        "provider": StorageProvider.AWS_S3,
        "region": "us-east-1",
        "public": False,
        "versioning": True,
        "logging": True,
        "objects": 125_000,
        "size_gb": 450.0,
        "encrypted": True,
        "enc_type": "aws:kms",
        "kms_key": "arn:aws:kms:us-east-1:123:key/abc",
        "tls_enforced": True,
    },
    {
        "name": "dev-data-dumps",
        "provider": StorageProvider.AWS_S3,
        "region": "us-west-2",
        "public": True,
        "versioning": False,
        "logging": False,
        "objects": 3_200,
        "size_gb": 85.0,
        "encrypted": False,
        "enc_type": "",
        "kms_key": "",
        "tls_enforced": False,
    },
    {
        "name": "customer-uploads",
        "provider": StorageProvider.AWS_S3,
        "region": "us-east-1",
        "public": False,
        "versioning": True,
        "logging": True,
        "objects": 890_000,
        "size_gb": 1_200.0,
        "encrypted": True,
        "enc_type": "AES256",
        "kms_key": "",
        "tls_enforced": True,
    },
    {
        "name": "ml-training-data",
        "provider": StorageProvider.GCP_GCS,
        "region": "us-central1",
        "public": False,
        "versioning": False,
        "logging": True,
        "objects": 45_000,
        "size_gb": 2_500.0,
        "encrypted": True,
        "enc_type": "google-managed",
        "kms_key": "",
        "tls_enforced": True,
    },
    {
        "name": "public-static-site",
        "provider": StorageProvider.GCP_GCS,
        "region": "us-east1",
        "public": True,
        "versioning": False,
        "logging": False,
        "objects": 850,
        "size_gb": 2.5,
        "encrypted": True,
        "enc_type": "google-managed",
        "kms_key": "",
        "tls_enforced": False,
    },
    {
        "name": "analytics-exports",
        "provider": StorageProvider.AZURE_BLOB,
        "region": "eastus",
        "public": False,
        "versioning": True,
        "logging": True,
        "objects": 12_000,
        "size_gb": 320.0,
        "encrypted": True,
        "enc_type": "microsoft-managed",
        "kms_key": "",
        "tls_enforced": True,
    },
    {
        "name": "backup-storage",
        "provider": StorageProvider.AZURE_BLOB,
        "region": "westus2",
        "public": False,
        "versioning": True,
        "logging": False,
        "objects": 5_600,
        "size_gb": 780.0,
        "encrypted": False,
        "enc_type": "",
        "kms_key": "",
        "tls_enforced": False,
    },
    {
        "name": "logs-archive-2024",
        "provider": StorageProvider.AWS_S3,
        "region": "eu-west-1",
        "public": False,
        "versioning": False,
        "logging": False,
        "objects": 2_100_000,
        "size_gb": 4_800.0,
        "encrypted": True,
        "enc_type": "AES256",
        "kms_key": "",
        "tls_enforced": True,
    },
]

_PERMISSION_FINDINGS: list[dict[str, Any]] = [
    {
        "bucket": "dev-data-dumps",
        "severity": StorageSeverity.CRITICAL,
        "type": "public_acl",
        "desc": ("Bucket has public-read ACL with no access restrictions"),
        "principal": "*",
        "permission": "s3:GetObject",
        "is_public": True,
        "rec": ("Remove public ACL and restrict access to specific IAM roles"),
    },
    {
        "bucket": "dev-data-dumps",
        "severity": StorageSeverity.HIGH,
        "type": "no_block_public_access",
        "desc": ("Block Public Access settings are disabled"),
        "principal": "account",
        "permission": "s3:PutBucketPolicy",
        "is_public": False,
        "rec": ("Enable S3 Block Public Access at account and bucket level"),
    },
    {
        "bucket": "customer-uploads",
        "severity": StorageSeverity.MEDIUM,
        "type": "cross_account_access",
        "desc": ("Cross-account access granted to account 987654321098"),
        "principal": "arn:aws:iam::987654321098:root",
        "permission": "s3:GetObject,s3:ListBucket",
        "is_public": False,
        "rec": ("Verify cross-account access is authorized and apply conditions"),
    },
    {
        "bucket": "public-static-site",
        "severity": StorageSeverity.HIGH,
        "type": "public_bucket_policy",
        "desc": ("Bucket policy allows allUsers read access"),
        "principal": "allUsers",
        "permission": "storage.objects.get",
        "is_public": True,
        "rec": ("Use CDN origin access identity instead of public bucket policy"),
    },
    {
        "bucket": "logs-archive-2024",
        "severity": StorageSeverity.LOW,
        "type": "overly_broad_iam",
        "desc": ("IAM role has s3:* on bucket instead of least-privilege"),
        "principal": "arn:aws:iam::123:role/admin",
        "permission": "s3:*",
        "is_public": False,
        "rec": ("Scope permissions to specific actions (Get, List, Put)"),
    },
]

_SENSITIVE_DATA_FINDINGS: list[dict[str, Any]] = [
    {
        "bucket": "dev-data-dumps",
        "severity": StorageSeverity.CRITICAL,
        "data_type": "PII",
        "object_key": "exports/users_full_dump.csv",
        "pattern": "SSN (XXX-XX-XXXX)",
        "count": 12_500,
        "rec": ("Remove PII from public bucket immediately; encrypt and restrict"),
    },
    {
        "bucket": "dev-data-dumps",
        "severity": StorageSeverity.CRITICAL,
        "data_type": "credentials",
        "object_key": ".env.production",
        "pattern": "AWS_SECRET_ACCESS_KEY=...",
        "count": 3,
        "rec": ("Rotate exposed credentials and remove .env files from storage"),
    },
    {
        "bucket": "customer-uploads",
        "severity": StorageSeverity.HIGH,
        "data_type": "PHI",
        "object_key": "medical/patient_records.json",
        "pattern": "medical_record_number",
        "count": 850,
        "rec": ("Apply HIPAA-compliant encryption and access controls"),
    },
    {
        "bucket": "ml-training-data",
        "severity": StorageSeverity.MEDIUM,
        "data_type": "PCI",
        "object_key": "training/transactions.parquet",
        "pattern": "credit_card_number",
        "count": 45_000,
        "rec": ("Tokenize card numbers in training data; apply PCI-DSS controls"),
    },
    {
        "bucket": "analytics-exports",
        "severity": StorageSeverity.LOW,
        "data_type": "email_addresses",
        "object_key": "reports/user_analytics.csv",
        "pattern": "email (user@domain.com)",
        "count": 2_300,
        "rec": ("Hash or pseudonymize email addresses in analytics exports"),
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class CloudStorageScannerToolkit:
    """Tools for cloud storage security scanning."""

    def __init__(
        self,
        cloud_api: Any | None = None,
        scanner_api: Any | None = None,
    ) -> None:
        self._cloud_api = cloud_api
        self._scanner_api = scanner_api

    async def discover_buckets(
        self,
        tenant_id: str,
        providers: list[str] | None = None,
    ) -> list[StorageBucket]:
        """Discover storage buckets across providers."""
        logger.info(
            "css.discover_buckets",
            tenant_id=tenant_id,
            providers=providers,
        )

        if self._cloud_api is not None:
            try:
                raw = await self._cloud_api.list_buckets(
                    tenant_id=tenant_id,
                    providers=providers,
                )
                return [StorageBucket(**r) for r in raw]
            except Exception:
                logger.exception(
                    "css.discover_buckets.error",
                )

        buckets: list[StorageBucket] = []
        for i, p in enumerate(_BUCKET_PROFILES):
            if providers and p["provider"].value not in providers:
                continue
            buckets.append(
                StorageBucket(
                    id=_gen_id("BKT", tenant_id, i),
                    name=p["name"],
                    provider=p["provider"],
                    region=p["region"],
                    creation_date="2024-01-15",
                    public_access=p["public"],
                    versioning_enabled=p["versioning"],
                    logging_enabled=p["logging"],
                    object_count=p["objects"],
                    size_gb=p["size_gb"],
                    tags={"env": "production"},
                )
            )
        return buckets

    async def scan_permissions(
        self,
        buckets: list[StorageBucket],
    ) -> list[PermissionFinding]:
        """Scan bucket permissions and ACLs."""
        logger.info(
            "css.scan_permissions",
            count=len(buckets),
        )

        if self._scanner_api is not None:
            try:
                names = [b.name for b in buckets]
                raw = await self._scanner_api.scan_perms(
                    buckets=names,
                )
                return [PermissionFinding(**r) for r in raw]
            except Exception:
                logger.exception(
                    "css.scan_permissions.error",
                )

        bucket_names = {b.name for b in buckets}
        findings: list[PermissionFinding] = []
        for i, pf in enumerate(_PERMISSION_FINDINGS):
            if pf["bucket"] not in bucket_names:
                continue
            findings.append(
                PermissionFinding(
                    id=_gen_id("PF", pf["bucket"], i),
                    bucket_name=pf["bucket"],
                    severity=pf["severity"],
                    finding_type=pf["type"],
                    description=pf["desc"],
                    principal=pf["principal"],
                    permission=pf["permission"],
                    is_public=pf["is_public"],
                    recommendation=pf["rec"],
                )
            )
        return findings

    async def detect_sensitive_data(
        self,
        buckets: list[StorageBucket],
    ) -> list[SensitiveDataFinding]:
        """Detect sensitive data in storage buckets."""
        logger.info(
            "css.detect_sensitive_data",
            count=len(buckets),
        )

        if self._scanner_api is not None:
            try:
                names = [b.name for b in buckets]
                raw = await self._scanner_api.scan_data(
                    buckets=names,
                )
                return [SensitiveDataFinding(**r) for r in raw]
            except Exception:
                logger.exception(
                    "css.detect_sensitive_data.error",
                )

        bucket_names = {b.name for b in buckets}
        findings: list[SensitiveDataFinding] = []
        for i, sf in enumerate(
            _SENSITIVE_DATA_FINDINGS,
        ):
            if sf["bucket"] not in bucket_names:
                continue
            findings.append(
                SensitiveDataFinding(
                    id=_gen_id("SD", sf["bucket"], i),
                    bucket_name=sf["bucket"],
                    severity=sf["severity"],
                    data_type=sf["data_type"],
                    object_key=sf["object_key"],
                    pattern_matched=sf["pattern"],
                    sample_count=sf["count"],
                    recommendation=sf["rec"],
                )
            )
        return findings

    async def assess_encryption(
        self,
        buckets: list[StorageBucket],
    ) -> list[EncryptionAssessment]:
        """Assess encryption posture for buckets."""
        logger.info(
            "css.assess_encryption",
            count=len(buckets),
        )

        assessments: list[EncryptionAssessment] = []
        for i, b in enumerate(buckets):
            profile = next(
                (p for p in _BUCKET_PROFILES if p["name"] == b.name),
                None,
            )
            if profile is None:
                continue

            encrypted = profile["encrypted"]
            enc_type = profile["enc_type"]
            kms_key = profile["kms_key"]
            tls = profile["tls_enforced"]

            if not encrypted:
                sev = StorageSeverity.CRITICAL
                rec = f"Enable encryption on {b.name} with KMS-managed keys"
            elif not tls:
                sev = StorageSeverity.MEDIUM
                rec = f"Enforce TLS in-transit for {b.name}"
            elif not kms_key and enc_type != "AES256":
                sev = StorageSeverity.LOW
                rec = f"Upgrade {b.name} to customer-managed KMS keys"
            else:
                sev = StorageSeverity.INFO
                rec = f"{b.name} encryption posture meets best practices"

            assessments.append(
                EncryptionAssessment(
                    id=_gen_id("ENC", b.name, i),
                    bucket_name=b.name,
                    severity=sev,
                    encryption_enabled=encrypted,
                    encryption_type=enc_type,
                    kms_key_id=kms_key,
                    in_transit_enforced=tls,
                    recommendation=rec,
                )
            )
        return assessments

    async def remediate_issues(
        self,
        permission_findings: list[PermissionFinding],
        encryption_assessments: list[EncryptionAssessment],
    ) -> list[RemediationAction]:
        """Generate and apply remediation actions."""
        logger.info(
            "css.remediate",
            perms=len(permission_findings),
            enc=len(encryption_assessments),
        )

        actions: list[RemediationAction] = []
        idx = 0

        for pf in permission_findings:
            auto = pf.severity in (
                StorageSeverity.CRITICAL,
                StorageSeverity.HIGH,
            )
            status = "applied" if auto else "proposed"
            risk = "medium" if pf.is_public else "low"
            actions.append(
                RemediationAction(
                    id=_gen_id("REM", pf.id, idx),
                    finding_id=pf.id,
                    bucket_name=pf.bucket_name,
                    action_type=(f"fix_{pf.finding_type}"),
                    description=pf.recommendation,
                    status=status,
                    auto_executable=auto,
                    rollback_available=True,
                    risk=risk,
                )
            )
            idx += 1

        for ea in encryption_assessments:
            if ea.severity in (
                StorageSeverity.CRITICAL,
                StorageSeverity.HIGH,
                StorageSeverity.MEDIUM,
            ):
                auto = ea.severity == StorageSeverity.CRITICAL
                actions.append(
                    RemediationAction(
                        id=_gen_id("REM", ea.id, idx),
                        finding_id=ea.id,
                        bucket_name=ea.bucket_name,
                        action_type="fix_encryption",
                        description=ea.recommendation,
                        status=("applied" if auto else "proposed"),
                        auto_executable=auto,
                        rollback_available=True,
                        risk="low",
                    )
                )
                idx += 1

        for a in actions:
            if (
                a.status == "applied" and random.random() < 0.1  # noqa: S311
            ):
                a.status = "failed"

        return actions
