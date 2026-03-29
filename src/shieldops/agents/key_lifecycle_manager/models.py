"""Key Lifecycle Manager Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class KeyStage(StrEnum):
    DISCOVER_KEYS = "discover_keys"
    AUDIT_CEREMONIES = "audit_ceremonies"
    CHECK_ROTATION = "check_rotation"
    ASSESS_COMPLIANCE = "assess_compliance"
    TRACK_ESCROW = "track_escrow"
    REPORT = "report"


class KeyType(StrEnum):
    SYMMETRIC = "symmetric"
    ASYMMETRIC = "asymmetric"
    HMAC = "hmac"
    SIGNING = "signing"
    ENCRYPTION = "encryption"
    WRAPPING = "wrapping"


class KeyStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    COMPROMISED = "compromised"
    PENDING_ROTATION = "pending_rotation"
    DEACTIVATED = "deactivated"
    DESTROYED = "destroyed"


class KeyLifecycleManagerState(BaseModel):
    request_id: str = ""
    stage: KeyStage = KeyStage.DISCOVER_KEYS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
