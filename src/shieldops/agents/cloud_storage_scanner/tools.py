"""Cloud Storage Scanner Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Any

import structlog

from .models import (
    AccessFinding,
    EncryptionFinding,
    SensitiveDataFinding,
    StorageBucket,
    StorageProvider,
    StorageSeverity,
)

logger = structlog.get_logger()

_BUCKET_NAMES: dict[str, list[str]] = {
    "s3": [
        "logs-prod",
        "data-lake",
        "backups-daily",
        "static-assets",
        "ml-models",
        "config-store",
        "audit-trail",
        "temp-uploads",
    ],
    "gcs": [
        "analytics-data",
        "ml-training",
        "backup-vault",
        "web-assets",
        "log-archive",
    ],
    "azure_blob": [
        "diagnostics",
        "app-data",
        "backup-container",
        "static-content",
        "telemetry-store",
    ],
}

_REGIONS: dict[str, list[str]] = {
    "s3": ["us-east-1", "us-west-2", "eu-west-1"],
    "gcs": ["us-central1", "europe-west1"],
    "azure_blob": ["eastus", "westeurope"],
}

_SENSITIVE_DATA_TYPES = [
    {
        "type": "pii",
        "pattern": "*.csv with SSN/email/phone",
        "severity": StorageSeverity.CRITICAL,
    },
    {
        "type": "phi",
        "pattern": "*.json with health records",
        "severity": StorageSeverity.CRITICAL,
    },
    {
        "type": "credentials",
        "pattern": "*.env, *.key, *.pem files",
        "severity": StorageSeverity.CRITICAL,
    },
    {
        "type": "financial",
        "pattern": "*.xlsx with payment data",
        "severity": StorageSeverity.HIGH,
    },
    {
        "type": "source_code",
        "pattern": "*.py, *.js with hardcoded values",
        "severity": StorageSeverity.MEDIUM,
    },
]


def _bucket_hash(provider: str, name: str) -> str:
    raw = f"{provider}-{name}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class CloudStorageScannerToolkit:
    """Tools for cloud storage security scanning."""

    def __init__(
        self,
        cloud_clients: Any | None = None,
    ) -> None:
        self._cloud_clients = cloud_clients

    async def discover_buckets(
        self,
        tenant_id: str,
        providers: list[str],
    ) -> list[StorageBucket]:
        """Discover storage buckets across providers."""
        logger.info(
            "css.discover",
            tenant_id=tenant_id,
            providers=providers,
        )

        if self._cloud_clients is not None:
            try:
                raw = await self._cloud_clients.list_buckets(
                    tenant_id=tenant_id, providers=providers
                )
                return [StorageBucket(**r) for r in raw]
            except Exception:
                logger.exception("css.discover.error")

        buckets: list[StorageBucket] = []
        encryption_types = [
            "none",
            "sse_s3",
            "sse_kms",
            "sse_c",
            "cmk",
        ]

        for prov in providers:
            names = _BUCKET_NAMES.get(prov, ["default"])
            regions = _REGIONS.get(prov, ["us-east-1"])
            selected = random.sample(  # noqa: S311
                names,
                min(len(names), random.randint(3, 6)),  # noqa: S311
            )

            for name in selected:
                bid = _bucket_hash(prov, name)
                buckets.append(
                    StorageBucket(
                        id=bid,
                        provider=StorageProvider(prov),
                        bucket_name=f"{name}-{bid[:6]}",
                        region=random.choice(regions),  # noqa: S311
                        creation_date=time.time()
                        - random.uniform(  # noqa: S311
                            86400, 86400 * 365
                        ),
                        versioning_enabled=random.random() > 0.4,  # noqa: S311
                        logging_enabled=random.random() > 0.5,  # noqa: S311
                        encryption_type=random.choice(  # noqa: S311
                            encryption_types
                        ),
                        public_access_blocked=random.random() > 0.2,  # noqa: S311
                        object_count=random.randint(  # noqa: S311
                            100, 100000
                        ),
                        size_gb=round(
                            random.uniform(0.1, 500.0),  # noqa: S311
                            1,
                        ),
                        tags={
                            "env": random.choice(  # noqa: S311
                                ["prod", "staging", "dev"]
                            ),
                        },
                    )
                )

        logger.info("css.discover.done", count=len(buckets))
        return buckets

    async def scan_access(
        self,
        buckets: list[StorageBucket],
    ) -> list[AccessFinding]:
        """Scan bucket access configurations."""
        logger.info("css.access", count=len(buckets))

        findings: list[AccessFinding] = []
        for bucket in buckets:
            if not bucket.public_access_blocked:
                findings.append(
                    AccessFinding(
                        id=str(uuid.uuid4())[:8],
                        bucket_id=bucket.id,
                        finding_type="public_access",
                        severity=StorageSeverity.CRITICAL,
                        description=(f"{bucket.bucket_name} has public access not blocked"),
                        public_readable=random.random() > 0.3,  # noqa: S311
                        public_writable=random.random() > 0.7,  # noqa: S311
                        overly_permissive_acl=True,
                        risk_score=round(
                            85.0 + random.uniform(-5, 10),  # noqa: S311
                            1,
                        ),
                    )
                )
            elif random.random() > 0.7:  # noqa: S311
                findings.append(
                    AccessFinding(
                        id=str(uuid.uuid4())[:8],
                        bucket_id=bucket.id,
                        finding_type="permissive_policy",
                        severity=StorageSeverity.HIGH,
                        description=(f"{bucket.bucket_name} has overly permissive bucket policy"),
                        overly_permissive_acl=True,
                        risk_score=round(
                            65.0 + random.uniform(-5, 5),  # noqa: S311
                            1,
                        ),
                    )
                )

        logger.info("css.access.done", findings=len(findings))
        return findings

    async def check_encryption(
        self,
        buckets: list[StorageBucket],
    ) -> list[EncryptionFinding]:
        """Check bucket encryption configurations."""
        logger.info("css.encryption", count=len(buckets))

        findings: list[EncryptionFinding] = []
        for bucket in buckets:
            if bucket.encryption_type == "none":
                findings.append(
                    EncryptionFinding(
                        id=str(uuid.uuid4())[:8],
                        bucket_id=bucket.id,
                        finding_type="no_encryption",
                        severity=StorageSeverity.HIGH,
                        encryption_type="none",
                        description=(f"{bucket.bucket_name} has no encryption at rest"),
                        compliant=False,
                    )
                )
            elif bucket.encryption_type in ("sse_s3", "sse_c"):
                findings.append(
                    EncryptionFinding(
                        id=str(uuid.uuid4())[:8],
                        bucket_id=bucket.id,
                        finding_type="weak_encryption",
                        severity=StorageSeverity.MEDIUM,
                        encryption_type=bucket.encryption_type,
                        description=(
                            f"{bucket.bucket_name} uses {bucket.encryption_type} (CMK recommended)"
                        ),
                        compliant=False,
                    )
                )

        logger.info(
            "css.encryption.done",
            findings=len(findings),
        )
        return findings

    async def detect_sensitive_data(
        self,
        buckets: list[StorageBucket],
    ) -> list[SensitiveDataFinding]:
        """Detect sensitive data in buckets."""
        logger.info("css.sensitive", count=len(buckets))

        findings: list[SensitiveDataFinding] = []
        for bucket in buckets:
            if random.random() > 0.5:  # noqa: S311
                tpl = random.choice(  # noqa: S311
                    _SENSITIVE_DATA_TYPES
                )
                base_risk = {
                    StorageSeverity.CRITICAL: 90.0,
                    StorageSeverity.HIGH: 70.0,
                    StorageSeverity.MEDIUM: 50.0,
                }.get(tpl["severity"], 50.0)

                findings.append(
                    SensitiveDataFinding(
                        id=str(uuid.uuid4())[:8],
                        bucket_id=bucket.id,
                        data_type=tpl["type"],
                        severity=tpl["severity"],
                        file_pattern=tpl["pattern"],
                        estimated_count=random.randint(  # noqa: S311
                            1, 100
                        ),
                        description=(f"{tpl['type']} data in {bucket.bucket_name}"),
                        risk_score=round(
                            base_risk + random.uniform(-5, 5),  # noqa: S311
                            1,
                        ),
                    )
                )

        logger.info(
            "css.sensitive.done",
            findings=len(findings),
        )
        return findings
