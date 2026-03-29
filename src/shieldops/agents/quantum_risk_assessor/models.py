"""State models for the Quantum Risk Assessor Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ────────────────────────────────────────────────


class QuantumAssessmentStage(StrEnum):
    """Workflow stages for quantum risk assessment."""

    SCAN_INFRASTRUCTURE = "scan_infrastructure"
    INVENTORY_ALGORITHMS = "inventory_algorithms"
    ASSESS_VULNERABILITY = "assess_vulnerability"
    SCORE_READINESS = "score_readiness"
    RECOMMEND_MIGRATION = "recommend_migration"
    REPORT = "report"


class QuantumThreatLevel(StrEnum):
    """Threat levels for quantum computing risk."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class CryptoAlgorithmType(StrEnum):
    """Types of cryptographic algorithms assessed."""

    RSA = "rsa"
    ECC = "ecc"
    DH = "dh"
    DSA = "dsa"
    AES = "aes"
    SHA = "sha"
    POST_QUANTUM = "post_quantum"


# ── Domain Models ───────────────────────────────────────────


class CryptoAsset(BaseModel):
    """A discovered cryptographic asset in infrastructure."""

    asset_id: str = ""
    hostname: str = ""
    service_name: str = ""
    algorithm: str = CryptoAlgorithmType.RSA
    key_size: int = 0
    protocol: str = ""
    certificate_expiry: str = ""
    is_quantum_vulnerable: bool = False
    threat_level: str = QuantumThreatLevel.MEDIUM
    metadata: dict[str, Any] = Field(default_factory=dict)


class AlgorithmInventory(BaseModel):
    """An inventoried cryptographic algorithm usage."""

    inventory_id: str = ""
    algorithm: str = CryptoAlgorithmType.RSA
    key_size: int = 0
    usage_count: int = 0
    services: list[str] = Field(default_factory=list)
    quantum_vulnerable: bool = True
    estimated_break_year: int = 0
    migration_priority: str = "medium"


class VulnerabilityAssessment(BaseModel):
    """A quantum vulnerability assessment for a crypto asset."""

    assessment_id: str = ""
    asset_id: str = ""
    algorithm: str = CryptoAlgorithmType.RSA
    threat_level: str = QuantumThreatLevel.MEDIUM
    shor_vulnerable: bool = False
    grover_vulnerable: bool = False
    harvest_now_risk: bool = False
    estimated_time_to_break_years: float = 0.0
    data_shelf_life_years: float = 0.0
    risk_score: float = 0.0


class ReadinessScore(BaseModel):
    """PQC migration readiness score."""

    category: str = ""
    score: float = 0.0
    max_score: float = 100.0
    findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class MigrationRecommendation(BaseModel):
    """A PQC migration recommendation."""

    recommendation_id: str = ""
    asset_id: str = ""
    current_algorithm: str = ""
    recommended_algorithm: str = ""
    priority: str = "medium"
    effort_weeks: float = 0.0
    risk_reduction: float = 0.0
    reasoning: str = ""


# ── Reasoning Step ──────────────────────────────────────────


class QuantumReasoningStep(BaseModel):
    """Audit trail entry for the quantum risk workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


# ── LangGraph State ─────────────────────────────────────────


class QuantumRiskAssessorState(BaseModel):
    """Full state for a quantum risk assessment workflow run."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: str = QuantumAssessmentStage.SCAN_INFRASTRUCTURE
    scan_config: dict[str, Any] = Field(default_factory=dict)

    # Stage outputs
    crypto_assets: list[CryptoAsset] = Field(default_factory=list)
    algorithm_inventory: list[AlgorithmInventory] = Field(default_factory=list)
    vulnerability_assessments: list[VulnerabilityAssessment] = Field(
        default_factory=list,
    )
    readiness_scores: list[ReadinessScore] = Field(default_factory=list)
    migration_recommendations: list[MigrationRecommendation] = Field(
        default_factory=list,
    )

    # Aggregates
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    total_risk_score: float = 0.0
    pqc_readiness_score: float = 0.0
    vulnerable_algorithm_count: int = 0
    critical_asset_count: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[QuantumReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
