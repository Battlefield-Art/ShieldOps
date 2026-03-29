"""Social Engineering Detector Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DetectionStage(StrEnum):
    COLLECT_SIGNALS = "collect_signals"
    ANALYZE_PATTERNS = "analyze_patterns"
    CLASSIFY_ATTACK = "classify_attack"
    ASSESS_RISK = "assess_risk"
    RECOMMEND = "recommend"
    REPORT = "report"


class AttackTechnique(StrEnum):
    PRETEXTING = "pretexting"
    BAITING = "baiting"
    QUID_PRO_QUO = "quid_pro_quo"
    TAILGATING = "tailgating"
    IMPERSONATION = "impersonation"
    VISHING = "vishing"


class ConfidenceLevel(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCERTAIN = "uncertain"
    FALSE_POSITIVE = "false_positive"


class SEIndicator(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class AttackProfile(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class DetectionAlert(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class SocialEngineeringDetectorState(BaseModel):
    request_id: str = ""
    stage: DetectionStage = DetectionStage.COLLECT_SIGNALS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
