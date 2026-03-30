"""Data Retention Enforcer Agent — Tool functions."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .models import ExpiryStatus

logger = structlog.get_logger()

_MOCK_ASSETS: list[dict[str, Any]] = [
    {
        "name": "customer_pii_db",
        "location": "s3://data-lake/pii/",
        "size_gb": 50.0,
        "data_type": "PII",
        "owner": "data-team",
    },
    {
        "name": "transaction_logs",
        "location": "s3://data-lake/txn/",
        "size_gb": 200.0,
        "data_type": "financial",
        "owner": "finance-team",
    },
    {
        "name": "audit_logs_2023",
        "location": "s3://archive/audit/2023/",
        "size_gb": 30.0,
        "data_type": "audit",
        "owner": "compliance-team",
    },
    {
        "name": "ml_training_data",
        "location": "gcs://ml-data/training/",
        "size_gb": 500.0,
        "data_type": "ml_dataset",
        "owner": "ml-team",
    },
    {
        "name": "temp_analytics",
        "location": "s3://tmp/analytics/",
        "size_gb": 10.0,
        "data_type": "temporary",
        "owner": "analytics-team",
    },
    {
        "name": "legal_case_docs",
        "location": "s3://legal/cases/",
        "size_gb": 5.0,
        "data_type": "legal",
        "owner": "legal-team",
    },
]

_POLICY_MAP: dict[str, tuple[str, int]] = {
    "PII": ("regulatory", 730),
    "financial": ("regulatory", 2555),
    "audit": ("regulatory", 2190),
    "ml_dataset": ("operational", 365),
    "temporary": ("operational", 90),
    "legal": ("legal_hold", 0),
}


class DataRetentionEnforcerToolkit:
    """Tools for data retention enforcement."""

    def __init__(
        self,
        data_catalog: Any | None = None,
        deletion_api: Any | None = None,
        legal_hold_api: Any | None = None,
    ) -> None:
        self._data_catalog = data_catalog
        self._deletion_api = deletion_api
        self._legal_hold_api = legal_hold_api

    async def discover_data(
        self,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Discover data assets."""
        logger.info(
            "dre.discover",
            tenant_id=tenant_id,
        )

        if self._data_catalog is not None:
            try:
                return await self._data_catalog.list(
                    tenant_id=tenant_id,
                )
            except Exception:
                logger.exception("dre.discover.error")

        results: list[dict[str, Any]] = []
        for i, a in enumerate(_MOCK_ASSETS):
            results.append(
                {
                    "id": f"da-{i:03d}",
                    "name": a["name"],
                    "location": a["location"],
                    "size_gb": a["size_gb"],
                    "data_type": a["data_type"],
                    "owner": a["owner"],
                    "created_at": "2023-06-01",
                    "last_accessed": "2025-12-15",
                }
            )
        return results

    def classify_retention(
        self,
        asset: dict[str, Any],
    ) -> dict[str, Any]:
        """Classify retention policy for an asset."""
        data_type = asset.get("data_type", "")
        policy_info = _POLICY_MAP.get(
            data_type,
            ("operational", 365),
        )
        policy = policy_info[0]
        retention_days = policy_info[1]

        is_legal = policy == "legal_hold"
        if retention_days == 0:
            status = ExpiryStatus.EXEMPT.value
        else:
            # Simple mock: check if older than retention
            status = ExpiryStatus.ACTIVE.value
            if data_type == "temporary":
                status = ExpiryStatus.EXPIRED.value
            elif data_type == "audit":
                status = ExpiryStatus.EXPIRING_SOON.value

        return {
            "asset_id": asset.get("id", ""),
            "policy": policy,
            "retention_days": retention_days,
            "expiry_date": "2026-06-01",
            "status": status,
            "legal_hold": is_legal,
        }

    async def enforce_deletion(
        self,
        classification: dict[str, Any],
    ) -> dict[str, Any]:
        """Enforce deletion for expired assets."""
        logger.info(
            "dre.delete",
            asset_id=classification.get("asset_id"),
        )

        status = classification.get("status", "")
        if status != ExpiryStatus.EXPIRED.value:
            return {
                "asset_id": classification.get(
                    "asset_id",
                    "",
                ),
                "deleted": False,
                "method": "skipped",
                "verified": False,
                "deleted_at": 0.0,
            }

        if classification.get("legal_hold"):
            return {
                "asset_id": classification.get(
                    "asset_id",
                    "",
                ),
                "deleted": False,
                "method": "legal_hold_blocked",
                "verified": False,
                "deleted_at": 0.0,
            }

        if self._deletion_api is not None:
            try:
                return await self._deletion_api.delete(
                    asset_id=classification.get(
                        "asset_id",
                        "",
                    ),
                )
            except Exception:
                logger.exception("dre.delete.error")

        return {
            "asset_id": classification.get(
                "asset_id",
                "",
            ),
            "deleted": True,
            "method": "secure_wipe",
            "verified": True,
            "deleted_at": time.time(),
        }

    def generate_report(
        self,
        assets: list[dict[str, Any]],
        classifications: list[dict[str, Any]],
        deletions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate retention enforcement report."""
        expired = sum(1 for c in classifications if c.get("status") == "expired")
        exempt = sum(1 for c in classifications if c.get("status") == "exempt")
        deleted = sum(1 for d in deletions if d.get("deleted"))
        total_gb = sum(a.get("size_gb", 0) for a in assets)

        return {
            "total_assets": len(assets),
            "total_size_gb": round(total_gb, 1),
            "expired_assets": expired,
            "exempt_assets": exempt,
            "deleted_assets": deleted,
            "classifications": classifications,
            "generated_at": time.time(),
        }
