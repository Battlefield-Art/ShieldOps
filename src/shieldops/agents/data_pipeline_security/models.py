"""Data Pipeline Security Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PipelineStage(StrEnum):
    SCAN_RAG = "scan_rag"
    AUDIT_DATA_FLOWS = "audit_data_flows"
    DETECT_POISONING = "detect_poisoning"
    ASSESS_PROVENANCE = "assess_provenance"
    ENFORCE_POLICIES = "enforce_policies"
    REPORT = "report"


class DataSourceType(StrEnum):
    VECTOR_DB = "vector_db"
    DOCUMENT_STORE = "document_store"
    MODEL_REGISTRY = "model_registry"
    TRAINING_DATA = "training_data"
    EMBEDDING_SERVICE = "embedding_service"
    API_ENDPOINT = "api_endpoint"


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --- Supporting models ---


class PoisoningFinding(BaseModel):
    """A data poisoning finding from pipeline scanning."""

    id: str = ""
    source: str = ""
    source_type: DataSourceType = DataSourceType.DOCUMENT_STORE
    poisoning_type: str = ""
    description: str = ""
    severity: RiskLevel = RiskLevel.MEDIUM
    confidence: float = 0.0
    mitre_technique: str = ""
    affected_records: int = 0


class DataFlowAnomaly(BaseModel):
    """An anomalous data flow detected in the pipeline."""

    id: str = ""
    source: str = ""
    destination: str = ""
    anomaly_type: str = ""
    description: str = ""
    severity: RiskLevel = RiskLevel.MEDIUM
    data_volume_gb: float = 0.0
    timestamp: float = 0.0


class ProvenanceRecord(BaseModel):
    """A provenance verification record for a model/data artifact."""

    id: str = ""
    artifact_name: str = ""
    artifact_type: str = ""
    origin: str = ""
    hash_digest: str = ""
    verified: bool = False
    risk_level: RiskLevel = RiskLevel.MEDIUM
    last_verified: float = 0.0


class PolicyViolation(BaseModel):
    """A data pipeline security policy violation."""

    id: str = ""
    policy_name: str = ""
    resource: str = ""
    violation_type: str = ""
    description: str = ""
    severity: RiskLevel = RiskLevel.MEDIUM
    auto_remediated: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


# --- Main state ---


class DataPipelineSecurityState(BaseModel):
    """Main state for the Data Pipeline Security agent graph."""

    request_id: str = ""
    stage: PipelineStage = PipelineStage.SCAN_RAG

    # Input
    pipeline_id: str = ""
    data_sources: list[dict[str, Any]] = Field(default_factory=list)
    scan_scope: list[str] = Field(default_factory=list)

    # Detection findings
    poisoning_findings: list[PoisoningFinding] = Field(default_factory=list)
    data_flow_anomalies: list[DataFlowAnomaly] = Field(default_factory=list)
    provenance_records: list[ProvenanceRecord] = Field(default_factory=list)
    policy_violations: list[PolicyViolation] = Field(default_factory=list)

    # Response
    policies_enforced: list[str] = Field(default_factory=list)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
