"""Model Security Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SecurityStage(StrEnum):
    SCAN_MODELS = "scan_models"
    VERIFY_PROVENANCE = "verify_provenance"
    DETECT_BACKDOORS = "detect_backdoors"
    ASSESS_INTEGRITY = "assess_integrity"
    EVALUATE_RISKS = "evaluate_risks"
    REPORT = "report"


class ThreatLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanVerdict(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    UNKNOWN = "unknown"
    QUARANTINED = "quarantined"


class ModelRecord(BaseModel):
    """A registered ML model under security governance."""

    model_id: str = ""
    name: str = ""
    version: str = ""
    framework: str = ""
    source_registry: str = ""
    file_hash: str = ""
    file_size_mb: float = 0.0
    last_scanned: str = ""
    tags: list[str] = Field(default_factory=list)


class ProvenanceRecord(BaseModel):
    """Provenance verification result for a model artifact."""

    model_id: str = ""
    publisher: str = ""
    signing_key: str = ""
    signature_valid: bool = False
    supply_chain_verified: bool = False
    training_data_hash: str = ""
    training_pipeline: str = ""
    license: str = ""
    known_vulnerabilities: list[str] = Field(default_factory=list)


class BackdoorIndicator(BaseModel):
    """Indicator of a potential backdoor in a model."""

    indicator_id: str = ""
    model_id: str = ""
    indicator_type: str = ""
    description: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    trigger_pattern: str = ""
    affected_layers: list[str] = Field(default_factory=list)
    mitre_technique: str = ""
    threat_level: ThreatLevel = ThreatLevel.MEDIUM


class IntegrityAssessment(BaseModel):
    """Integrity assessment result for a model."""

    model_id: str = ""
    hash_verified: bool = False
    weight_drift_score: float = Field(default=0.0, ge=0.0, le=100.0)
    architecture_anomalies: list[str] = Field(default_factory=list)
    serialization_safe: bool = True
    pickle_scan_result: str = ""
    verdict: ScanVerdict = ScanVerdict.UNKNOWN
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)


class ModelSecurityState(BaseModel):
    """Main state for the Model Security agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SecurityStage = SecurityStage.SCAN_MODELS

    # Target models to scan
    target_models: list[str] = Field(default_factory=list)

    # Discovered model records
    models: list[dict[str, Any]] = Field(default_factory=list)

    # Provenance verification results
    provenance_records: list[dict[str, Any]] = Field(default_factory=list)

    # Backdoor detection results
    backdoor_indicators: list[dict[str, Any]] = Field(default_factory=list)

    # Integrity assessments
    integrity_assessments: list[dict[str, Any]] = Field(default_factory=list)

    # Risk evaluation
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    overall_verdict: ScanVerdict = ScanVerdict.UNKNOWN
    risk_factors: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    report_summary: str = ""

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
