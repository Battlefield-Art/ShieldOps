"""Training Data Validator Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ValidationStage(StrEnum):
    PROFILE_DATA = "profile_data"
    CHECK_LABELS = "check_labels"
    DETECT_POISONING = "detect_poisoning"
    ANALYZE_BIAS = "analyze_bias"
    VALIDATE_PROVENANCE = "validate_provenance"
    REPORT = "report"


class DataIssue(StrEnum):
    LABEL_ERROR = "label_error"
    POISONED_SAMPLE = "poisoned_sample"
    DISTRIBUTION_SHIFT = "distribution_shift"
    MISSING_VALUES = "missing_values"
    DUPLICATE = "duplicate"
    OUTLIER = "outlier"


class DataSource(StrEnum):
    INTERNAL = "internal"
    PUBLIC = "public"
    VENDOR = "vendor"
    SYNTHETIC = "synthetic"
    CROWD_SOURCED = "crowd_sourced"
    SCRAPED = "scraped"


class ValidationCheck(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class DatasetProfile(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class IssueReport(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class TrainingDataValidatorState(BaseModel):
    request_id: str = ""
    stage: ValidationStage = ValidationStage.PROFILE_DATA
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
