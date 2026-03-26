"""State models for the Ransomware Forensics Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ForensicsStage(StrEnum):
    """Stages of the ransomware forensic investigation."""

    COLLECT_ARTIFACTS = "collect_artifacts"
    ANALYZE_ATTACK_CHAIN = "analyze_attack_chain"
    IDENTIFY_VARIANT = "identify_variant"
    ASSESS_BLAST_RADIUS = "assess_blast_radius"
    RECOMMEND_RECOVERY = "recommend_recovery"
    REPORT = "report"


class RansomwareVariant(StrEnum):
    """Known ransomware variant families."""

    LOCKBIT = "lockbit"
    BLACKCAT = "blackcat"
    CLOP = "clop"
    ROYAL = "royal"
    PLAY = "play"
    RHYSIDA = "rhysida"
    UNKNOWN = "unknown"


class BlastRadiusLevel(StrEnum):
    """Blast radius severity levels."""

    CONTAINED = "contained"
    SPREADING = "spreading"
    WIDESPREAD = "widespread"
    CATASTROPHIC = "catastrophic"


class ForensicArtifact(BaseModel):
    """A forensic artifact collected during investigation."""

    artifact_id: str = ""
    artifact_type: str = ""
    source_system: str = ""
    file_path: str = ""
    file_extension: str = ""
    hash_sha256: str = ""
    encryption_detected: bool = False
    ransom_note_found: bool = False
    timestamp: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackChainAnalysis(BaseModel):
    """Reconstructed attack chain from forensic evidence."""

    initial_access_vector: str = ""
    lateral_movement_path: list[str] = Field(default_factory=list)
    privilege_escalation: list[str] = Field(default_factory=list)
    persistence_mechanisms: list[str] = Field(default_factory=list)
    c2_servers: list[str] = Field(default_factory=list)
    exfiltration_indicators: list[str] = Field(default_factory=list)
    dwell_time_hours: float = 0.0
    mitre_techniques: list[str] = Field(default_factory=list)
    timeline_events: list[dict[str, Any]] = Field(default_factory=list)


class VariantIdentification(BaseModel):
    """Ransomware variant identification result."""

    variant: str = RansomwareVariant.UNKNOWN
    confidence: float = 0.0
    file_extension_pattern: str = ""
    encryption_algorithm: str = ""
    ransom_note_pattern: str = ""
    c2_signature: str = ""
    known_decryptor_available: bool = False
    threat_actor_group: str = ""
    iocs: list[str] = Field(default_factory=list)


class BlastRadiusAssessment(BaseModel):
    """Blast radius assessment for the ransomware incident."""

    level: str = BlastRadiusLevel.CONTAINED
    affected_hosts: list[str] = Field(default_factory=list)
    affected_services: list[str] = Field(default_factory=list)
    affected_cloud_accounts: list[str] = Field(default_factory=list)
    affected_identities: list[str] = Field(default_factory=list)
    predicted_spread_hosts: list[str] = Field(default_factory=list)
    predicted_spread_services: list[str] = Field(default_factory=list)
    data_encrypted_gb: float = 0.0
    data_exfiltrated_gb: float = 0.0
    business_impact_score: float = 0.0
    propagation_vectors: list[str] = Field(default_factory=list)


class RecoveryRecommendation(BaseModel):
    """Recovery recommendation for ransomware incident."""

    priority: int = 0
    action: str = ""
    target_system: str = ""
    estimated_time_hours: float = 0.0
    requires_backup_restore: bool = False
    backup_available: bool = False
    backup_integrity_verified: bool = False
    risk_of_reinfection: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the forensics workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class RansomwareForensicsState(BaseModel):
    """Full state for ransomware forensic investigation."""

    # Input
    tenant_id: str = ""
    incident_id: str = ""
    target_systems: list[str] = Field(default_factory=list)

    # Stage tracking
    current_stage: str = ForensicsStage.COLLECT_ARTIFACTS

    # Artifact collection
    artifacts_collected: list[dict[str, Any]] = Field(default_factory=list)

    # Attack chain analysis
    attack_chain: dict[str, Any] = Field(default_factory=dict)

    # Variant identification
    variant_identified: dict[str, Any] = Field(default_factory=dict)

    # Blast radius
    blast_radius: dict[str, Any] = Field(default_factory=dict)

    # Recovery plan
    recovery_plan: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    affected_systems_count: int = 0
    estimated_data_encrypted_gb: float = 0.0

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str | None = None
