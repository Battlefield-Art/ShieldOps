"""Data Retention Enforcer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DREStage(StrEnum):
    DISCOVER_DATA = "discover_data"
    CLASSIFY_RETENTION = "classify_retention"
    CHECK_EXPIRY = "check_expiry"
    ENFORCE_DELETION = "enforce_deletion"
    VERIFY_COMPLIANCE = "verify_compliance"
    REPORT = "report"


class RetentionPolicy(StrEnum):
    REGULATORY = "regulatory"
    CONTRACTUAL = "contractual"
    OPERATIONAL = "operational"
    LEGAL_HOLD = "legal_hold"
    ARCHIVAL = "archival"
    PERMANENT = "permanent"


class ExpiryStatus(StrEnum):
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    ACTIVE = "active"
    EXEMPT = "exempt"
    UNKNOWN = "unknown"


class DataAsset(BaseModel):
    """A discovered data asset."""

    id: str = ""
    name: str = ""
    location: str = ""
    size_gb: float = 0.0
    data_type: str = ""
    owner: str = ""
    created_at: str = ""
    last_accessed: str = ""


class RetentionClassification(BaseModel):
    """Retention policy classification for a data asset."""

    asset_id: str = ""
    policy: RetentionPolicy = RetentionPolicy.OPERATIONAL
    retention_days: int = 365
    expiry_date: str = ""
    status: ExpiryStatus = ExpiryStatus.ACTIVE
    legal_hold: bool = False


class DeletionRecord(BaseModel):
    """Record of a data deletion action."""

    asset_id: str = ""
    deleted: bool = False
    method: str = ""
    verified: bool = False
    deleted_at: float = 0.0


class DataRetentionEnforcerState(BaseModel):
    """Main state for the Data Retention Enforcer."""

    request_id: str = ""
    tenant_id: str = ""
    stage: DREStage = DREStage.DISCOVER_DATA

    # Pipeline data
    assets: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    deletions: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    total_assets: int = 0
    expired_assets: int = 0
    deleted_assets: int = 0
    exempt_assets: int = 0

    # Output
    report: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
