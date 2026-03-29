"""Consent Manager Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ConsentStage(StrEnum):
    COLLECT_CONSENTS = "collect_consents"
    VALIDATE_PURPOSES = "validate_purposes"
    CHECK_EXPIRY = "check_expiry"
    ENFORCE_PREFERENCES = "enforce_preferences"
    AUDIT = "audit"
    REPORT = "report"


class ConsentType(StrEnum):
    EXPLICIT = "explicit"
    IMPLIED = "implied"
    OPT_IN = "opt_in"
    OPT_OUT = "opt_out"
    LEGITIMATE_INTEREST = "legitimate_interest"
    CONTRACTUAL = "contractual"


class ConsentStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"
    PENDING = "pending"
    INVALID = "invalid"


class ConsentManagerState(BaseModel):
    request_id: str = ""
    stage: ConsentStage = ConsentStage.COLLECT_CONSENTS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
