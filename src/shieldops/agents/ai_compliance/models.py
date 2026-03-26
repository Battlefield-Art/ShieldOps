"""AI Compliance Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ComplianceStage(StrEnum):
    COLLECT_INVENTORY = "collect_inventory"
    CLASSIFY_RISK = "classify_risk"
    ASSESS_REQUIREMENTS = "assess_requirements"
    EVALUATE_CONTROLS = "evaluate_controls"
    GENERATE_EVIDENCE = "generate_evidence"
    REPORT = "report"


class RiskClassification(StrEnum):
    UNACCEPTABLE = "unacceptable"
    HIGH_RISK = "high_risk"
    LIMITED_RISK = "limited_risk"
    MINIMAL_RISK = "minimal_risk"


class ControlStatus(StrEnum):
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    MISSING = "missing"
    NOT_APPLICABLE = "not_applicable"


class AISystemRecord(BaseModel):
    """An AI system registered in the enterprise inventory."""

    system_id: str = ""
    name: str = ""
    description: str = ""
    purpose: str = ""
    domain: str = ""
    model_type: str = ""
    deployment_env: str = ""
    data_categories: list[str] = Field(default_factory=list)
    stakeholders: list[str] = Field(default_factory=list)
    risk_classification: RiskClassification = RiskClassification.MINIMAL_RISK
    tags: dict[str, str] = Field(default_factory=dict)


class ComplianceRequirement(BaseModel):
    """A compliance requirement from a specific framework."""

    requirement_id: str = ""
    framework: str = ""
    article: str = ""
    title: str = ""
    description: str = ""
    risk_tiers: list[RiskClassification] = Field(default_factory=list)
    mandatory: bool = True
    evidence_needed: list[str] = Field(default_factory=list)


class ControlAssessment(BaseModel):
    """Assessment of a control against a compliance requirement."""

    assessment_id: str = ""
    requirement_id: str = ""
    system_id: str = ""
    framework: str = ""
    control_name: str = ""
    status: ControlStatus = ControlStatus.MISSING
    findings: str = ""
    remediation: str = ""
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    evidence_refs: list[str] = Field(default_factory=list)


class EvidencePackage(BaseModel):
    """Evidence package supporting a compliance assessment."""

    evidence_id: str = ""
    system_id: str = ""
    framework: str = ""
    evidence_type: str = ""
    title: str = ""
    description: str = ""
    artifacts: list[str] = Field(default_factory=list)
    generated_at: str = ""
    valid_until: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AIComplianceState(BaseModel):
    """Main state for the AI Compliance agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: ComplianceStage = ComplianceStage.COLLECT_INVENTORY

    # Target frameworks to assess against
    frameworks: list[str] = Field(default_factory=list)

    # Discovered AI system inventory
    systems: list[AISystemRecord] = Field(default_factory=list)

    # Risk classifications per system
    classifications: dict[str, str] = Field(default_factory=dict)

    # Applicable requirements
    requirements: list[ComplianceRequirement] = Field(default_factory=list)

    # Control assessments
    assessments: list[ControlAssessment] = Field(default_factory=list)

    # Evidence packages
    evidence: list[EvidencePackage] = Field(default_factory=list)

    # Overall compliance scores per framework
    compliance_scores: dict[str, float] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
