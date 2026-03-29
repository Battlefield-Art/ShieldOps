"""Model Explainability Auditor Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AuditStage(StrEnum):
    COLLECT_PREDICTIONS = "collect_predictions"
    COMPUTE_IMPORTANCE = "compute_importance"
    ANALYZE_SHAP = "analyze_shap"
    CHECK_FAIRNESS = "check_fairness"
    GENERATE_REPORT = "generate_report"
    REPORT = "report"


class ExplainMethod(StrEnum):
    SHAP = "shap"
    LIME = "lime"
    FEATURE_IMPORTANCE = "feature_importance"
    ATTENTION_MAP = "attention_map"
    COUNTERFACTUAL = "counterfactual"
    PARTIAL_DEPENDENCE = "partial_dependence"


class ComplianceLevel(StrEnum):
    FULLY_EXPLAINABLE = "fully_explainable"
    PARTIALLY_EXPLAINABLE = "partially_explainable"
    OPAQUE = "opaque"
    NON_COMPLIANT = "non_compliant"


class FeatureImportance(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class ExplainResult(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class FairnessMetric(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class ModelExplainabilityAuditorState(BaseModel):
    request_id: str = ""
    stage: AuditStage = AuditStage.COLLECT_PREDICTIONS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
