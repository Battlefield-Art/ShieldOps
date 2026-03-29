"""Data Masking Engine Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class MaskingStage(StrEnum):
    DISCOVER_DATA = "discover_data"
    CLASSIFY_SENSITIVITY = "classify_sensitivity"
    SELECT_TECHNIQUE = "select_technique"
    APPLY_MASKS = "apply_masks"
    VALIDATE = "validate"
    REPORT = "report"


class MaskingTechnique(StrEnum):
    REDACTION = "redaction"
    SUBSTITUTION = "substitution"
    SHUFFLING = "shuffling"
    ENCRYPTION = "encryption"
    TOKENIZATION = "tokenization"
    NULLING = "nulling"


class SensitivityLevel(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"  # noqa: S105


class DataMaskingEngineState(BaseModel):
    request_id: str = ""
    stage: MaskingStage = MaskingStage.DISCOVER_DATA
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
