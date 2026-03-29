"""Inference Attack Detector Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AttackStage(StrEnum):
    COLLECT_QUERIES = "collect_queries"
    ANALYZE_PATTERNS = "analyze_patterns"
    CLASSIFY_ATTACK = "classify_attack"
    ASSESS_IMPACT = "assess_impact"
    MITIGATE = "mitigate"
    REPORT = "report"


class AttackType(StrEnum):
    MODEL_INVERSION = "model_inversion"
    MEMBERSHIP_INFERENCE = "membership_inference"
    MODEL_EXTRACTION = "model_extraction"
    ADVERSARIAL_EXAMPLE = "adversarial_example"
    DATA_RECONSTRUCTION = "data_reconstruction"
    PROMPT_INJECTION = "prompt_injection"


class ThreatLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class InferenceQuery(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class AttackIndicator(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class MitigationAction(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class InferenceAttackDetectorState(BaseModel):
    request_id: str = ""
    stage: AttackStage = AttackStage.COLLECT_QUERIES
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
