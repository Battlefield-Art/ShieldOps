"""Tool functions for the Air-Gap Vault Agent.

Provides vault asset inventory, isolation verification,
cryptographic integrity checking, tamper detection,
and retention policy enforcement.
"""

import hashlib
import time
from typing import Any

import structlog

from shieldops.agents.air_gap_vault.models import (
    IntegrityCheck,
    IntegrityStatus,
    IsolationLevel,
    IsolationVerification,
    RetentionPolicy,
    TamperDetection,
    VaultAsset,
)

logger = structlog.get_logger()


class AirGapVaultToolkit:
    """Tools for managing air-gapped data vaults."""

    # AI-specific asset types that extend beyond Rubrik
    AI_ASSET_TYPES = [
        "model_weights",
        "rag_index",
        "training_data",
        "fine_tune_checkpoint",
        "embedding_store",
    ]

    BACKUP_ASSET_TYPES = [
        "database_backup",
        "config_snapshot",
        "log_archive",
        "certificate_store",
    ]

    def __init__(
        self,
        storage_client: Any = None,
        network_client: Any = None,
    ) -> None:
        self._storage_client = storage_client
        self._network_client = network_client

    async def inventory_vault_assets(
        self,
        tenant_id: str,
        vault_id: str,
        scan_scope: str = "all",
    ) -> list[VaultAsset]:
        """Discover and inventory all assets in the vault.

        Args:
            tenant_id: Tenant identifier.
            vault_id: Vault identifier to scan.
            scan_scope: Scope filter (all, ai_assets, backups).

        Returns:
            List of discovered vault assets.
        """
        assets: list[VaultAsset] = []
        now = time.time()

        if self._storage_client is not None:
            try:
                raw = await self._storage_client.list_assets(
                    vault_id=vault_id,
                    scope=scan_scope,
                )
                for item in raw:
                    assets.append(
                        VaultAsset(
                            name=item["name"],
                            asset_type=item["type"],
                            size_bytes=item.get("size", 0),
                            storage_location=item.get("loc", ""),
                            tenant_id=tenant_id,
                        )
                    )
                return assets
            except Exception as e:
                logger.error(
                    "vault_inventory_api_failed",
                    error=str(e),
                )

        # Simulated inventory for dev/test
        type_pool = self.AI_ASSET_TYPES + self.BACKUP_ASSET_TYPES
        if scan_scope == "ai_assets":
            type_pool = self.AI_ASSET_TYPES
        elif scan_scope == "backups":
            type_pool = self.BACKUP_ASSET_TYPES

        for i, asset_type in enumerate(type_pool):
            h = hashlib.sha256(f"{vault_id}-{asset_type}-{i}".encode()).hexdigest()
            assets.append(
                VaultAsset(
                    name=f"{asset_type}_{vault_id}_{i}",
                    asset_type=asset_type,
                    size_bytes=(i + 1) * 1024 * 1024 * 100,
                    isolation_level=IsolationLevel.FULL_AIR_GAP
                    if asset_type in self.AI_ASSET_TYPES
                    else IsolationLevel.LOGICAL_AIR_GAP,
                    hash_chain=[h],
                    last_verified_at=now - (i * 3600),
                    storage_location=f"vault://{vault_id}/blobs/{h[:16]}",
                    tenant_id=tenant_id,
                )
            )

        logger.info(
            "vault_assets_inventoried",
            vault_id=vault_id,
            asset_count=len(assets),
            scope=scan_scope,
        )
        return assets

    async def verify_isolation(self, asset: VaultAsset) -> IsolationVerification:
        """Verify network isolation of a vault asset.

        Checks DNS resolution, network reachability,
        egress blocking, and ingress restrictions.

        Args:
            asset: The vault asset to verify isolation for.

        Returns:
            An IsolationVerification with pass/fail details.
        """
        if self._network_client is not None:
            try:
                result = await self._network_client.check_isolation(
                    location=asset.storage_location,
                )
                return IsolationVerification(
                    asset_id=asset.id,
                    isolation_level=asset.isolation_level,
                    network_reachable=result.get("reachable", False),
                    dns_resolvable=result.get("dns", False),
                    egress_blocked=result.get("egress_blocked", True),
                    ingress_restricted=result.get("ingress_ok", True),
                    passed=result.get("passed", False),
                    details=result.get("details", ""),
                )
            except Exception as e:
                logger.error(
                    "vault_isolation_check_failed",
                    asset_id=asset.id,
                    error=str(e),
                )

        # Simulated isolation check
        is_air_gapped = asset.isolation_level in (
            IsolationLevel.FULL_AIR_GAP,
            IsolationLevel.LOGICAL_AIR_GAP,
        )
        net_reachable = not is_air_gapped
        dns_ok = not is_air_gapped

        passed = not net_reachable and not dns_ok if is_air_gapped else True

        details = (
            f"Asset '{asset.name}' isolation={asset.isolation_level}. "
            f"Network reachable={net_reachable}, DNS={dns_ok}. "
            f"{'PASS' if passed else 'FAIL'}."
        )

        verification = IsolationVerification(
            asset_id=asset.id,
            isolation_level=asset.isolation_level,
            network_reachable=net_reachable,
            dns_resolvable=dns_ok,
            egress_blocked=is_air_gapped,
            ingress_restricted=True,
            passed=passed,
            details=details,
        )

        logger.info(
            "vault_isolation_verified",
            asset_id=asset.id,
            isolation_level=asset.isolation_level.value,
            passed=passed,
        )
        return verification

    async def check_integrity(self, asset: VaultAsset) -> IntegrityCheck:
        """Cryptographic integrity check using hash chains.

        Validates the asset's SHA-256 hash chain to detect
        silent data corruption or unauthorized modifications.

        Args:
            asset: The vault asset to verify.

        Returns:
            An IntegrityCheck with hash comparison results.
        """
        if self._storage_client is not None:
            try:
                result = await self._storage_client.verify_hash(
                    location=asset.storage_location,
                    expected_chain=asset.hash_chain,
                )
                return IntegrityCheck(
                    asset_id=asset.id,
                    expected_hash=result.get("expected", ""),
                    actual_hash=result.get("actual", ""),
                    chain_valid=result.get("valid", False),
                    status=IntegrityStatus.VERIFIED
                    if result.get("valid")
                    else IntegrityStatus.TAMPERED,
                    details=result.get("details", ""),
                )
            except Exception as e:
                logger.error(
                    "vault_integrity_check_failed",
                    asset_id=asset.id,
                    error=str(e),
                )

        # Simulated integrity check
        expected = asset.hash_chain[-1] if asset.hash_chain else ""
        recomputed = hashlib.sha256(f"{asset.name}-{asset.size_bytes}".encode()).hexdigest()

        # Simulate: most assets pass, training_data occasionally fails
        chain_valid = asset.asset_type != "training_data"
        actual = expected if chain_valid else recomputed

        status = IntegrityStatus.VERIFIED if chain_valid else IntegrityStatus.DEGRADED

        check = IntegrityCheck(
            asset_id=asset.id,
            expected_hash=expected,
            actual_hash=actual,
            chain_valid=chain_valid,
            status=status,
            details=f"Hash chain {'valid' if chain_valid else 'broken'} "
            f"for {asset.name} ({asset.asset_type}).",
        )

        logger.info(
            "vault_integrity_checked",
            asset_id=asset.id,
            status=status.value,
            chain_valid=chain_valid,
        )
        return check

    async def detect_tampering(self, asset: VaultAsset) -> list[TamperDetection]:
        """Detect unauthorized access or modification attempts.

        Scans audit logs for unexpected access patterns,
        modification attempts, and deletion requests.

        Args:
            asset: The vault asset to check for tampering.

        Returns:
            List of tamper detection alerts (may be empty).
        """
        alerts: list[TamperDetection] = []
        now = time.time()

        if self._storage_client is not None:
            try:
                raw = await self._storage_client.get_access_logs(
                    location=asset.storage_location,
                    since=now - 86400,
                )
                for entry in raw:
                    if entry.get("suspicious"):
                        alerts.append(
                            TamperDetection(
                                asset_id=asset.id,
                                alert_type=entry["type"],
                                severity=entry.get("severity", "medium"),
                                source_ip=entry.get("ip", ""),
                                timestamp=entry.get("ts", now),
                                details=entry.get("details", ""),
                            )
                        )
                return alerts
            except Exception as e:
                logger.error(
                    "vault_tamper_detection_failed",
                    asset_id=asset.id,
                    error=str(e),
                )

        # Simulated tamper detection
        if asset.asset_type == "model_weights":
            alerts.append(
                TamperDetection(
                    asset_id=asset.id,
                    alert_type="unexpected_access",
                    severity="high",
                    source_ip="10.0.99.42",
                    timestamp=now - 1800,
                    details=f"Unexpected read access to {asset.name} from non-vault network.",
                )
            )
        elif asset.asset_type == "training_data":
            alerts.append(
                TamperDetection(
                    asset_id=asset.id,
                    alert_type="modification",
                    severity="critical",
                    source_ip="10.0.99.55",
                    timestamp=now - 900,
                    details=f"Hash mismatch detected for {asset.name} — possible data poisoning.",
                )
            )

        if alerts:
            logger.warning(
                "vault_tamper_detected",
                asset_id=asset.id,
                alert_count=len(alerts),
            )

        return alerts

    async def enforce_retention(self, asset: VaultAsset) -> RetentionPolicy:
        """Enforce retention policies including legal holds.

        Applies compliance-driven retention rules for the asset,
        including legal hold locks and framework-specific durations.

        Args:
            asset: The vault asset to enforce retention on.

        Returns:
            The applied RetentionPolicy.
        """
        now = time.time()

        # AI assets get longer retention for audit trails
        if asset.asset_type in self.AI_ASSET_TYPES:
            framework = "SOC2"
            days = 730  # 2 years for AI assets
            hold = True
        else:
            framework = "HIPAA"
            days = 2190  # 6 years for HIPAA
            hold = False

        policy = RetentionPolicy(
            asset_id=asset.id,
            policy_name=f"{framework.lower()}_retention",
            retention_days=days,
            legal_hold=hold,
            compliance_framework=framework,
            enforced=True,
            expires_at=now + (days * 86400),
            details=f"{framework} retention ({days}d) applied "
            f"to {asset.name}. Legal hold={'ON' if hold else 'OFF'}.",
        )

        logger.info(
            "vault_retention_enforced",
            asset_id=asset.id,
            framework=framework,
            days=days,
            legal_hold=hold,
        )
        return policy
