"""Privacy Engineering Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PrivacyStage(StrEnum):
    SCAN_PIPELINES = "scan_pipelines"
    ASSESS_ANONYMIZATION = "assess_anonymization"
    VALIDATE_DIFFERENTIAL_PRIVACY = "validate_differential_privacy"
    AUDIT_PETS = "audit_pets"
    CHECK_COMPLIANCE = "check_compliance"
    REPORT = "report"


class PrivacyTechnique(StrEnum):
    DIFFERENTIAL_PRIVACY = "differential_privacy"
    K_ANONYMITY = "k_anonymity"
    L_DIVERSITY = "l_diversity"
    T_CLOSENESS = "t_closeness"
    HOMOMORPHIC_ENCRYPTION = "homomorphic_encryption"
    SECURE_MULTIPARTY = "secure_multiparty"


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class DataPipeline(BaseModel):
    """A data pipeline to be assessed for privacy compliance."""

    id: str = ""
    name: str = ""
    pipeline_type: str = ""  # etl / streaming / ml_training / analytics / api
    owner: str = ""
    data_sources: list[str] = Field(default_factory=list)
    data_sinks: list[str] = Field(default_factory=list)
    records_per_day: int = 0
    contains_pii: bool = False
    last_audited: float = 0.0


class AnonymizationFinding(BaseModel):
    """Result of anonymization quality assessment on a pipeline."""

    id: str = ""
    pipeline_id: str = ""
    technique_used: PrivacyTechnique = PrivacyTechnique.K_ANONYMITY
    risk_level: RiskLevel = RiskLevel.MEDIUM
    k_value: int = 0  # k-anonymity parameter
    epsilon: float = 0.0  # differential privacy epsilon
    delta: float = 0.0  # differential privacy delta
    quasi_identifiers: list[str] = Field(default_factory=list)
    re_identification_risk: float = 0.0  # 0.0 to 1.0
    compliant: bool = False
    gap_description: str = ""


class PETImplementation(BaseModel):
    """A Privacy Enhancing Technology implementation record."""

    id: str = ""
    pipeline_id: str = ""
    technique: PrivacyTechnique = PrivacyTechnique.DIFFERENTIAL_PRIVACY
    library: str = ""  # opendp / google_dp / pysyft / tensorflow_privacy
    version: str = ""
    config: dict[str, Any] = Field(default_factory=dict)
    validated: bool = False
    validation_errors: list[str] = Field(default_factory=list)


class ComplianceMapping(BaseModel):
    """Mapping of a privacy finding to a regulatory requirement."""

    id: str = ""
    finding_id: str = ""
    regulation: str = ""  # GDPR / CCPA / HIPAA / LGPD / PIPL
    article: str = ""
    requirement: str = ""
    compliant: bool = False
    gap_description: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class PrivacyEngineeringState(BaseModel):
    """Main state for the Privacy Engineering graph."""

    # Input
    request_id: str = ""
    stage: PrivacyStage = PrivacyStage.SCAN_PIPELINES
    tenant_id: str = ""

    # Data
    pipelines: list[dict[str, Any]] = Field(default_factory=list)
    anonymization_findings: list[dict[str, Any]] = Field(default_factory=list)
    pet_implementations: list[dict[str, Any]] = Field(default_factory=list)
    compliance_mappings: list[dict[str, Any]] = Field(default_factory=list)

    # Stats
    stats: dict[str, Any] = Field(default_factory=dict)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
