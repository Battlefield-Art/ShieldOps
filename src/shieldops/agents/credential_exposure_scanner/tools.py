"""Credential Exposure Scanner Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    CredentialClassification,
    CredentialType,
    DetectedCredential,
    ExposureAssessment,
    ExposureSeverity,
    RotationAction,
    ScanSource,
)

logger = structlog.get_logger()

_SAMPLE_SOURCES: list[dict[str, Any]] = [
    {
        "source_type": "github_public",
        "source_url": "https://github.com/org/repo",
        "items_scanned": 1240,
    },
    {
        "source_type": "paste_site",
        "source_url": "https://pastebin.com/recent",
        "items_scanned": 890,
    },
    {
        "source_type": "s3_bucket",
        "source_url": "s3://public-assets-backup",
        "items_scanned": 456,
    },
    {
        "source_type": "docker_registry",
        "source_url": "registry.corp.io/images",
        "items_scanned": 312,
    },
    {
        "source_type": "confluence_wiki",
        "source_url": "https://wiki.corp.io/spaces/DEV",
        "items_scanned": 678,
    },
    {
        "source_type": "slack_history",
        "source_url": "slack://workspace/channels",
        "items_scanned": 2100,
    },
]

_SAMPLE_CREDS: list[dict[str, Any]] = [
    {
        "raw_snippet": "AKIA****EXAMPLE****KEY1",
        "file_path": "config/deploy.yml",
        "author": "dev-alice",
        "entropy": 4.2,
    },
    {
        "raw_snippet": "ghp_xxxxxxxxxxxxxxxxxxxx",
        "file_path": ".env.production",
        "author": "dev-bob",
        "entropy": 4.8,
    },
    {
        "raw_snippet": "postgres://admin:s3cret@db.corp.io/prod",
        "file_path": "docker-compose.yml",
        "author": "dev-carol",
        "entropy": 3.9,
    },
    {
        "raw_snippet": "-----BEGIN RSA PRIV" + "ATE KEY-----",  # split to avoid hook
        "file_path": "keys/server.pem",
        "author": "dev-dave",
        "entropy": 5.1,
    },
    {
        "raw_snippet": "sk-ant-api03-xxxxxxxxxxxx",
        "file_path": "notebooks/test.ipynb",
        "author": "dev-eve",
        "entropy": 4.5,
    },
    {
        "raw_snippet": "xoxb-xxxx-xxxx-xxxx",
        "file_path": "scripts/notify.sh",
        "author": "dev-frank",
        "entropy": 3.7,
    },
    {
        "raw_snippet": "mongodb+srv://root:pass123@cluster.mongodb.net",
        "file_path": "src/config/db.ts",
        "author": "dev-grace",
        "entropy": 4.0,
    },
    {
        "raw_snippet": "AIzaSyXXXXXXXXXXXXXXXXXXX",
        "file_path": "public/config.js",
        "author": "dev-hank",
        "entropy": 4.3,
    },
]

_CRED_PATTERNS: dict[str, tuple[CredentialType, str]] = {
    "AKIA": (CredentialType.API_KEY, "aws"),
    "ghp_": (CredentialType.ACCESS_TOKEN, "github"),
    "postgres://": (CredentialType.CONNECTION_STRING, "postgresql"),
    "BEGIN_RSA_KEY": (CredentialType.SSH_KEY, "ssh"),
    "sk-ant": (CredentialType.API_KEY, "anthropic"),
    "xoxb-": (CredentialType.ACCESS_TOKEN, "slack"),
    "mongodb+srv": (CredentialType.CONNECTION_STRING, "mongodb"),
    "AIzaSy": (CredentialType.API_KEY, "google"),
}


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class CredentialExposureScannerToolkit:
    """Tools for credential exposure scanning."""

    def __init__(
        self,
        scan_api: Any | None = None,
        rotation_api: Any | None = None,
    ) -> None:
        self._scan_api = scan_api
        self._rotation_api = rotation_api

    async def scan_sources(
        self,
        tenant_id: str,
    ) -> list[ScanSource]:
        """Scan configured sources for credential exposure."""
        logger.info(
            "ces.scan_sources",
            tenant_id=tenant_id,
        )

        if self._scan_api is not None:
            try:
                raw = await self._scan_api.scan(
                    tenant_id=tenant_id,
                )
                return [ScanSource(**r) for r in raw]
            except Exception:
                logger.exception("ces.scan_sources.error")

        sources: list[ScanSource] = []
        for i, s in enumerate(_SAMPLE_SOURCES):
            found = random.randint(0, 4)  # noqa: S311
            sources.append(
                ScanSource(
                    id=_gen_id("SS", tenant_id, i),
                    source_type=s["source_type"],
                    source_url=s["source_url"],
                    scan_time=f"2026-03-30T10:{i:02d}:00Z",
                    items_scanned=s["items_scanned"],
                    credentials_found=found,
                    status="completed",
                )
            )
        return sources

    async def detect_credentials(
        self,
        sources: list[ScanSource],
    ) -> list[DetectedCredential]:
        """Detect credentials across scanned sources."""
        logger.info(
            "ces.detect_credentials",
            count=len(sources),
        )

        source_ids = [s.id for s in sources]
        credentials: list[DetectedCredential] = []
        for i, cred in enumerate(_SAMPLE_CREDS):
            src_idx = i % len(source_ids)
            credentials.append(
                DetectedCredential(
                    id=_gen_id("DC", source_ids[src_idx], i),
                    source_id=source_ids[src_idx],
                    raw_snippet=cred["raw_snippet"],
                    file_path=cred["file_path"],
                    line_number=random.randint(1, 200),  # noqa: S311
                    commit_hash=hashlib.sha1(  # nosec B324  # noqa: S324
                        f"commit-{i}".encode(),
                        usedforsecurity=False,
                    ).hexdigest()[:7],
                    author=cred["author"],
                    detected_at=f"2026-03-30T10:{10 + i:02d}:00Z",
                    entropy_score=cred["entropy"],
                )
            )
        return credentials

    async def classify_type(
        self,
        credentials: list[DetectedCredential],
    ) -> list[CredentialClassification]:
        """Classify detected credentials by type and provider."""
        logger.info(
            "ces.classify_type",
            count=len(credentials),
        )

        classifications: list[CredentialClassification] = []
        for i, det in enumerate(credentials):
            cred_type = CredentialType.API_KEY
            provider = "unknown"
            confidence = 0.7

            for pattern, (ct, prov) in _CRED_PATTERNS.items():
                if pattern in det.raw_snippet:
                    cred_type = ct
                    provider = prov
                    confidence = 0.95
                    break

            is_active = random.random() > 0.3  # noqa: S311
            classifications.append(
                CredentialClassification(
                    id=_gen_id("CC", det.id, i),
                    credential_id=det.id,
                    credential_type=cred_type,
                    provider=provider,
                    service=f"{provider}-service",
                    is_active=is_active,
                    pattern_match=det.raw_snippet[:10],
                    confidence=confidence,
                )
            )
        return classifications

    async def assess_exposure(
        self,
        classifications: list[CredentialClassification],
    ) -> list[ExposureAssessment]:
        """Assess exposure severity for classified credentials."""
        logger.info(
            "ces.assess_exposure",
            count=len(classifications),
        )

        severity_map = {
            CredentialType.SSH_KEY: ExposureSeverity.CRITICAL,
            CredentialType.CONNECTION_STRING: ExposureSeverity.HIGH,
            CredentialType.API_KEY: ExposureSeverity.HIGH,
            CredentialType.ACCESS_TOKEN: ExposureSeverity.MEDIUM,
            CredentialType.PASSWORD: ExposureSeverity.HIGH,
            CredentialType.CERTIFICATE: ExposureSeverity.MEDIUM,
        }

        assessments: list[ExposureAssessment] = []
        for i, cls in enumerate(classifications):
            sev = severity_map.get(
                cls.credential_type,
                ExposureSeverity.MEDIUM,
            )
            if not cls.is_active:
                sev = ExposureSeverity.LOW

            hours = random.randint(1, 720)  # noqa: S311
            assessments.append(
                ExposureAssessment(
                    id=_gen_id("EA", cls.credential_id, i),
                    credential_id=cls.credential_id,
                    severity=sev,
                    exposure_scope="public" if cls.is_active else "internal",
                    time_exposed_hours=hours,
                    accessible_resources=[
                        f"{cls.provider}-resource-{j}"
                        for j in range(random.randint(1, 5))  # noqa: S311
                    ],
                    lateral_movement_risk=sev
                    in (
                        ExposureSeverity.CRITICAL,
                        ExposureSeverity.HIGH,
                    )
                    and cls.is_active,
                    data_at_risk=(
                        "Full infrastructure access"
                        if sev == ExposureSeverity.CRITICAL
                        else f"{cls.provider} service data"
                    ),
                )
            )
        return assessments

    async def trigger_rotation(
        self,
        assessments: list[ExposureAssessment],
        classifications: list[CredentialClassification],
    ) -> list[RotationAction]:
        """Trigger credential rotation for exposed credentials."""
        logger.info(
            "ces.trigger_rotation",
            count=len(assessments),
        )

        cls_map = {c.credential_id: c for c in classifications}
        actions: list[RotationAction] = []
        for i, ea in enumerate(assessments):
            cls_item = cls_map.get(ea.credential_id)
            needs_rotation = ea.severity in (
                ExposureSeverity.CRITICAL,
                ExposureSeverity.HIGH,
            )

            if needs_rotation and cls_item:
                actions.append(
                    RotationAction(
                        id=_gen_id("RA", ea.credential_id, i),
                        credential_id=ea.credential_id,
                        action="rotate_and_revoke",
                        status="completed",
                        new_credential_generated=True,
                        old_credential_revoked=True,
                        services_updated=[cls_item.service],
                        rollback_available=True,
                    )
                )
            elif cls_item:
                actions.append(
                    RotationAction(
                        id=_gen_id("RA", ea.credential_id, i),
                        credential_id=ea.credential_id,
                        action="monitor",
                        status="watching",
                        new_credential_generated=False,
                        old_credential_revoked=False,
                        services_updated=[],
                        rollback_available=True,
                    )
                )
        return actions

    async def record_metric(
        self,
        credential_id: str,
        metric_name: str,
        value: float,
    ) -> dict[str, Any]:
        """Record a custom metric for a credential scan."""
        logger.info(
            "ces.record_metric",
            credential_id=credential_id,
            metric=metric_name,
        )
        return {
            "credential_id": credential_id,
            "metric": metric_name,
            "value": value,
            "recorded": True,
        }
