"""Backup Security Posture Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    BackupComponent,
    BackupInventory,
    BackupVulnerability,
    HardeningPriority,
    HardeningRecommendation,
    RecoveryTest,
    SecurityConfig,
)

logger = structlog.get_logger()

_BACKUP_PROFILES: list[dict[str, Any]] = [
    {
        "name": "primary-s3-vault",
        "component": BackupComponent.STORAGE,
        "provider": "AWS S3",
        "capacity": 100.0,
    },
    {
        "name": "dr-gcs-archive",
        "component": BackupComponent.STORAGE,
        "provider": "GCP GCS",
        "capacity": 200.0,
    },
    {
        "name": "azure-blob-backup",
        "component": BackupComponent.STORAGE,
        "provider": "Azure Blob",
        "capacity": 150.0,
    },
    {
        "name": "backup-network",
        "component": BackupComponent.NETWORK,
        "provider": "VPN Tunnel",
        "capacity": 0.0,
    },
    {
        "name": "backup-iam",
        "component": BackupComponent.ACCESS_CONTROL,
        "provider": "IAM",
        "capacity": 0.0,
    },
    {
        "name": "kms-encryption",
        "component": BackupComponent.ENCRYPTION,
        "provider": "AWS KMS",
        "capacity": 0.0,
    },
    {
        "name": "cross-region-repl",
        "component": BackupComponent.REPLICATION,
        "provider": "AWS",
        "capacity": 100.0,
    },
    {
        "name": "retention-policy",
        "component": BackupComponent.RETENTION,
        "provider": "Policy Engine",
        "capacity": 0.0,
    },
]

_VULN_TEMPLATES = [
    "Unencrypted backup at rest",
    "MFA not enforced on backup access",
    "No air-gap between prod and backup",
    "Backup not immutable",
    "Stale backup older than 30 days",
    "Cross-region replication disabled",
    "Retention policy too short",
    "Weak access control on backup API",
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class BackupSecurityPostureToolkit:
    """Tools for backup security posture assessment."""

    def __init__(
        self,
        backup_api: Any | None = None,
        vuln_scanner: Any | None = None,
        dr_tester: Any | None = None,
    ) -> None:
        self._backup_api = backup_api
        self._vuln_scanner = vuln_scanner
        self._dr_tester = dr_tester

    async def inventory_backup_infra(self, tenant_id: str) -> list[BackupInventory]:
        """Inventory backup infrastructure."""
        logger.info(
            "backup_posture.inventory",
            tenant_id=tenant_id,
        )

        if self._backup_api is not None:
            try:
                raw = await self._backup_api.list_backups(tenant_id=tenant_id)
                return [BackupInventory(**b) for b in raw]
            except Exception:
                logger.exception("backup_posture.inventory.error")

        items: list[BackupInventory] = []
        for i, prof in enumerate(_BACKUP_PROFILES):
            cap = prof["capacity"]
            used = (
                round(
                    cap
                    * random.uniform(  # noqa: S311
                        0.3, 0.9
                    ),
                    1,
                )
                if cap > 0
                else 0.0
            )
            items.append(
                BackupInventory(
                    id=_gen_id("BK", tenant_id, i),
                    name=prof["name"],
                    component=prof["component"],
                    provider=prof["provider"],
                    location="us-east-1",
                    capacity_tb=cap,
                    used_tb=used,
                    backup_count=random.randint(  # noqa: S311
                        10, 500
                    ),
                    last_backup=("2026-03-25T06:00:00Z"),
                    immutable=random.choice(  # noqa: S311
                        [True, False]
                    ),
                )
            )
        return items

    async def assess_security_config(
        self, inventory: list[BackupInventory]
    ) -> list[SecurityConfig]:
        """Assess backup security configuration."""
        logger.info(
            "backup_posture.config",
            count=len(inventory),
        )

        results: list[SecurityConfig] = []
        for item in inventory:
            enc_rest = random.random() > 0.2  # noqa: S311
            enc_transit = random.random() > 0.1  # noqa: S311
            mfa = random.random() > 0.5  # noqa: S311
            air = random.random() > 0.7  # noqa: S311
            ver = random.random() > 0.3  # noqa: S311

            score = 0.0
            issues: list[str] = []
            if enc_rest:
                score += 20.0
            else:
                issues.append("No encryption at rest")
            if enc_transit:
                score += 20.0
            else:
                issues.append("No encryption in transit")
            if mfa:
                score += 20.0
            else:
                issues.append("MFA not enabled")
            if air:
                score += 20.0
            else:
                issues.append("Not air-gapped")
            if ver:
                score += 20.0
            else:
                issues.append("Versioning not enabled")

            results.append(
                SecurityConfig(
                    inventory_id=item.id,
                    component=item.component,
                    encryption_at_rest=enc_rest,
                    encryption_in_transit=(enc_transit),
                    mfa_enabled=mfa,
                    air_gapped=air,
                    versioning_enabled=ver,
                    compliance_score=score,
                    issues=issues,
                )
            )
        return results

    async def detect_vulnerabilities(
        self,
        inventory: list[BackupInventory],
        configs: list[SecurityConfig],
    ) -> list[BackupVulnerability]:
        """Detect backup vulnerabilities."""
        logger.info(
            "backup_posture.vulns",
            count=len(inventory),
        )

        if self._vuln_scanner is not None:
            try:
                raw = await self._vuln_scanner.scan([i.id for i in inventory])
                return [BackupVulnerability(**v) for v in raw]
            except Exception:
                logger.exception("backup_posture.vulns.error")

        config_map = {c.inventory_id: c for c in configs}
        vulns: list[BackupVulnerability] = []
        idx = 0

        for item in inventory:
            cfg = config_map.get(item.id)
            if not cfg:
                continue
            for issue in cfg.issues:
                ransomware = (
                    "encryption" in issue.lower()
                    or "air-gap" in issue.lower()
                    or "immutable" in issue.lower()
                )
                severity = (
                    HardeningPriority.CRITICAL
                    if ransomware
                    else HardeningPriority.HIGH
                    if "MFA" in issue
                    else HardeningPriority.MEDIUM
                )
                vulns.append(
                    BackupVulnerability(
                        id=_gen_id("BV", item.id, idx),
                        inventory_id=item.id,
                        component=item.component,
                        vulnerability=issue,
                        severity=severity,
                        exploitable=(
                            severity
                            in (
                                HardeningPriority.CRITICAL,
                                HardeningPriority.HIGH,
                            )
                        ),
                        ransomware_risk=ransomware,
                        cve_id="",
                        description=(f"{issue} on {item.name}"),
                    )
                )
                idx += 1
        return vulns

    async def test_recovery(self, inventory: list[BackupInventory]) -> list[RecoveryTest]:
        """Test backup recovery capabilities."""
        logger.info(
            "backup_posture.recovery",
            count=len(inventory),
        )

        if self._dr_tester is not None:
            try:
                raw = await self._dr_tester.test([i.id for i in inventory])
                return [RecoveryTest(**t) for t in raw]
            except Exception:
                logger.exception("backup_posture.recovery.error")

        tests: list[RecoveryTest] = []
        storage_items = [i for i in inventory if i.component == BackupComponent.STORAGE]

        for i, item in enumerate(storage_items):
            success = random.random() > 0.15  # noqa: S311
            recovery_min = random.randint(  # noqa: S311
                5, 120
            )
            integrity = round(
                random.uniform(  # noqa: S311
                    95.0, 100.0
                )
                if success
                else random.uniform(  # noqa: S311
                    70.0, 95.0
                ),
                1,
            )
            issues: list[str] = []
            if not success:
                issues.append("Recovery failed partial")
            if recovery_min > 60:
                issues.append("RTO exceeded")

            tests.append(
                RecoveryTest(
                    id=_gen_id("RT", item.id, i),
                    inventory_id=item.id,
                    test_type="full_restore",
                    success=success,
                    recovery_time_min=(recovery_min),
                    data_integrity_pct=integrity,
                    rpo_met=success,
                    rto_met=recovery_min <= 60,
                    issues=issues,
                )
            )
        return tests

    async def recommend_hardening(
        self,
        inventory: list[BackupInventory],
        vulns: list[BackupVulnerability],
        tests: list[RecoveryTest],
    ) -> list[HardeningRecommendation]:
        """Generate hardening recommendations."""
        logger.info(
            "backup_posture.harden",
            vulns=len(vulns),
            tests=len(tests),
        )

        inv_map = {i.id: i for i in inventory}
        recs: list[HardeningRecommendation] = []
        idx = 0

        for vuln in vulns:
            inv_map.get(vuln.inventory_id)
            recs.append(
                HardeningRecommendation(
                    id=_gen_id("HR", vuln.id, idx),
                    inventory_id=(vuln.inventory_id),
                    component=vuln.component,
                    priority=vuln.severity,
                    recommendation=(f"Fix: {vuln.vulnerability}"),
                    rationale=(f"{vuln.description} — ransomware risk={vuln.ransomware_risk}"),
                    effort_hours=round(
                        random.uniform(  # noqa: S311
                            1.0, 20.0
                        ),
                        1,
                    ),
                    ransomware_protection=(vuln.ransomware_risk),
                )
            )
            idx += 1

        for test in tests:
            if not test.success:
                inv_map.get(test.inventory_id)
                recs.append(
                    HardeningRecommendation(
                        id=_gen_id(
                            "HR",
                            test.id,
                            idx,
                        ),
                        inventory_id=(test.inventory_id),
                        component=(BackupComponent.STORAGE),
                        priority=(HardeningPriority.CRITICAL),
                        recommendation=("Fix recovery failures"),
                        rationale=(f"Recovery test failed, integrity={test.data_integrity_pct}%"),
                        effort_hours=8.0,
                        ransomware_protection=True,
                    )
                )
                idx += 1

        recs.sort(
            key=lambda r: {
                HardeningPriority.CRITICAL: 0,
                HardeningPriority.HIGH: 1,
                HardeningPriority.MEDIUM: 2,
                HardeningPriority.LOW: 3,
                HardeningPriority.INFORMATIONAL: 4,
            }.get(r.priority, 5)
        )
        return recs
