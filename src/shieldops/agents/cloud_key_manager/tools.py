"""Cloud Key Manager Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any
from uuid import uuid4

import structlog

from .models import (
    CloudKey,
    KeyProvider,
    KeyRisk,
    KeyRiskAssessment,
    KeyUsage,
    PolicyEnforcement,
    RotationAudit,
)

logger = structlog.get_logger()

_SAMPLE_KEYS: list[dict[str, Any]] = [
    {
        "provider": "aws_kms",
        "alias": "prod-data-encryption",
        "algorithm": "AES-256",
        "state": "enabled",
        "region": "us-east-1",
        "rotation_days": 120,
    },
    {
        "provider": "aws_kms",
        "alias": "staging-secrets",
        "algorithm": "AES-256",
        "state": "enabled",
        "region": "us-west-2",
        "rotation_days": 45,
    },
    {
        "provider": "gcp_kms",
        "alias": "gcp-app-signing",
        "algorithm": "RSA-2048",
        "state": "enabled",
        "region": "us-central1",
        "rotation_days": 200,
    },
    {
        "provider": "gcp_kms",
        "alias": "gcp-data-key",
        "algorithm": "AES-256",
        "state": "enabled",
        "region": "europe-west1",
        "rotation_days": 60,
    },
    {
        "provider": "azure_key_vault",
        "alias": "az-tls-cert-key",
        "algorithm": "RSA-4096",
        "state": "enabled",
        "region": "eastus",
        "rotation_days": 180,
    },
    {
        "provider": "azure_key_vault",
        "alias": "az-db-encryption",
        "algorithm": "AES-256",
        "state": "disabled",
        "region": "westeurope",
        "rotation_days": 400,
    },
    {
        "provider": "hashicorp_vault",
        "alias": "vault-transit-key",
        "algorithm": "AES-256-GCM",
        "state": "enabled",
        "region": "on-prem",
        "rotation_days": 30,
    },
    {
        "provider": "aws_kms",
        "alias": "legacy-backup-key",
        "algorithm": "DES-128",
        "state": "enabled",
        "region": "us-east-1",
        "rotation_days": 900,
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class CloudKeyManagerToolkit:
    """Tools for cloud KMS key lifecycle management."""

    def __init__(
        self,
        kms_client: Any | None = None,
        vault_client: Any | None = None,
    ) -> None:
        self._kms_client = kms_client
        self._vault_client = vault_client

    async def discover_keys(
        self,
        tenant_id: str,
    ) -> list[CloudKey]:
        """Discover keys across cloud KMS providers."""
        logger.info(
            "ckm.discover_keys",
            tenant_id=tenant_id,
        )

        if self._kms_client is not None:
            try:
                raw = await self._kms_client.list_keys(
                    tenant_id=tenant_id,
                )
                return [CloudKey(**r) for r in raw]
            except Exception:
                logger.exception("ckm.discover_keys.error")

        keys: list[CloudKey] = []
        for i, k in enumerate(_SAMPLE_KEYS):
            _usage = random.randint(100, 50000)  # noqa: S311
            keys.append(
                CloudKey(
                    id=_gen_id("CK", tenant_id, i),
                    provider=KeyProvider(k["provider"]),
                    key_id=str(uuid4()),
                    alias=k["alias"],
                    algorithm=k["algorithm"],
                    state=k["state"],
                    created_at="2025-01-15T00:00:00Z",
                    last_rotated=f"2026-{max(1, 3 - k['rotation_days'] // 60):02d}-01T00:00:00Z",
                    rotation_days=k["rotation_days"],
                    region=k["region"],
                    usage_count=_usage,
                )
            )
        return keys

    async def audit_rotation(
        self,
        keys: list[CloudKey],
    ) -> list[RotationAudit]:
        """Audit key rotation compliance."""
        logger.info(
            "ckm.audit_rotation",
            count=len(keys),
        )

        audits: list[RotationAudit] = []
        for i, k in enumerate(keys):
            policy_max = 90
            compliant = k.rotation_days <= policy_max
            rec = "Compliant" if compliant else f"Rotate immediately ({k.rotation_days}d overdue)"
            auto_rotate = k.rotation_days < 60 and k.state == "enabled"
            audits.append(
                RotationAudit(
                    id=_gen_id("RA", k.id, i),
                    key_id=k.id,
                    provider=k.provider,
                    last_rotation=k.last_rotated,
                    days_since_rotation=k.rotation_days,
                    policy_max_days=policy_max,
                    compliant=compliant,
                    auto_rotate_enabled=auto_rotate,
                    recommendation=rec,
                )
            )
        return audits

    async def check_usage(
        self,
        keys: list[CloudKey],
    ) -> list[KeyUsage]:
        """Analyze key usage patterns."""
        logger.info(
            "ckm.check_usage",
            count=len(keys),
        )

        usages: list[KeyUsage] = []
        for i, k in enumerate(keys):
            encrypt = random.randint(0, k.usage_count)  # noqa: S311
            decrypt = random.randint(0, k.usage_count - encrypt)  # noqa: S311
            sign = k.usage_count - encrypt - decrypt
            unused = random.randint(0, 90) if k.state == "disabled" else 0  # noqa: S311
            svcs = ["lambda", "s3", "rds"] if "aws" in k.provider.value else ["app-engine"]
            usages.append(
                KeyUsage(
                    id=_gen_id("KU", k.id, i),
                    key_id=k.id,
                    encrypt_ops=encrypt,
                    decrypt_ops=decrypt,
                    sign_ops=max(sign, 0),
                    total_ops_30d=k.usage_count,
                    last_used="2026-03-29T12:00:00Z" if k.state == "enabled" else "",
                    unused_days=unused,
                    services=svcs,
                )
            )
        return usages

    async def assess_risk(
        self,
        keys: list[CloudKey],
        audits: list[RotationAudit],
    ) -> list[KeyRiskAssessment]:
        """Assess risk for each key."""
        logger.info(
            "ckm.assess_risk",
            count=len(keys),
        )

        audit_map = {a.key_id: a for a in audits}
        assessments: list[KeyRiskAssessment] = []
        for i, k in enumerate(keys):
            findings: list[str] = []
            risk = KeyRisk.LOW

            audit = audit_map.get(k.id)
            if audit and not audit.compliant:
                findings.append(f"Rotation overdue: {k.rotation_days}d")
                risk = KeyRisk.HIGH

            if k.algorithm in ("DES-128", "3DES", "RC4"):
                findings.append(f"Weak algorithm: {k.algorithm}")
                risk = KeyRisk.CRITICAL

            if k.state == "disabled":
                findings.append("Key disabled but not deleted")
                risk = max(risk, KeyRisk.MEDIUM, key=lambda r: list(KeyRisk).index(r))

            quantum_safe = k.algorithm in ("AES-256", "AES-256-GCM")
            agility = round(random.uniform(0.3, 1.0), 2)  # noqa: S311

            if not findings:
                findings.append("No issues found")
                risk = KeyRisk.COMPLIANT

            assessments.append(
                KeyRiskAssessment(
                    id=_gen_id("KR", k.id, i),
                    key_id=k.id,
                    risk=risk,
                    findings=findings,
                    crypto_agility_score=agility,
                    quantum_safe=quantum_safe,
                    cross_region_backup=k.provider != KeyProvider.ON_PREMISE_HSM,
                )
            )
        return assessments

    async def enforce_policy(
        self,
        assessments: list[KeyRiskAssessment],
    ) -> list[PolicyEnforcement]:
        """Enforce key management policies."""
        logger.info(
            "ckm.enforce_policy",
            count=len(assessments),
        )

        results: list[PolicyEnforcement] = []
        for i, a in enumerate(assessments):
            if a.risk in (KeyRisk.CRITICAL, KeyRisk.HIGH):
                results.append(
                    PolicyEnforcement(
                        id=_gen_id("PE", a.key_id, i),
                        key_id=a.key_id,
                        action="schedule_rotation",
                        status="enforced",
                        rotation_scheduled=True,
                        policy_applied="mandatory-90d-rotation",
                        rollback_available=True,
                    )
                )
            elif a.risk == KeyRisk.MEDIUM:
                results.append(
                    PolicyEnforcement(
                        id=_gen_id("PE", a.key_id, i),
                        key_id=a.key_id,
                        action="flag_review",
                        status="pending_review",
                        rotation_scheduled=False,
                        policy_applied="review-required",
                        rollback_available=True,
                    )
                )
            else:
                results.append(
                    PolicyEnforcement(
                        id=_gen_id("PE", a.key_id, i),
                        key_id=a.key_id,
                        action="monitor",
                        status="compliant",
                        rotation_scheduled=False,
                        policy_applied="standard-monitoring",
                        rollback_available=True,
                    )
                )
        return results

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Record a metric for observability."""
        _tags = tags or {}
        logger.info(
            "ckm.record_metric",
            metric=metric_name,
            value=value,
            tags=_tags,
        )
        return {
            "metric": metric_name,
            "value": value,
            "tags": _tags,
            "recorded": True,
        }
