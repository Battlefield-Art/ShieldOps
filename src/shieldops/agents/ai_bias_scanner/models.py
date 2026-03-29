"""AI Bias Scanner Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ScanStage(StrEnum):
    COLLECT_DATA = "collect_data"
    IDENTIFY_GROUPS = "identify_groups"
    COMPUTE_METRICS = "compute_metrics"
    ASSESS_FAIRNESS = "assess_fairness"
    RECOMMEND = "recommend"
    REPORT = "report"


class BiasMetric(StrEnum):
    DEMOGRAPHIC_PARITY = "demographic_parity"
    EQUALIZED_ODDS = "equalized_odds"
    DISPARATE_IMPACT = "disparate_impact"
    CALIBRATION = "calibration"
    PREDICTIVE_EQUALITY = "predictive_equality"
    INDIVIDUAL_FAIRNESS = "individual_fairness"


class FairnessLevel(StrEnum):
    FAIR = "fair"
    MARGINAL = "marginal"
    BIASED = "biased"
    SEVERELY_BIASED = "severely_biased"
    UNKNOWN = "unknown"


class BiasResult(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class ProtectedGroup(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class FairnessReport(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class AIBiasScannerState(BaseModel):
    request_id: str = ""
    stage: ScanStage = ScanStage.COLLECT_DATA
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
