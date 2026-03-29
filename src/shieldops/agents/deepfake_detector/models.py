"""Deepfake Detector Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DetectionStage(StrEnum):
    INGEST_MEDIA = "ingest_media"
    ANALYZE_ARTIFACTS = "analyze_artifacts"
    CHECK_PROVENANCE = "check_provenance"
    CLASSIFY_AUTHENTICITY = "classify_authenticity"
    GENERATE_EVIDENCE = "generate_evidence"
    REPORT = "report"


class MediaType(StrEnum):
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    TEXT = "text"
    DOCUMENT = "document"
    MULTIMODAL = "multimodal"


class AuthenticityVerdict(StrEnum):
    AUTHENTIC = "authentic"
    LIKELY_AUTHENTIC = "likely_authentic"
    UNCERTAIN = "uncertain"
    LIKELY_SYNTHETIC = "likely_synthetic"
    SYNTHETIC = "synthetic"


class MediaSubmission(BaseModel):
    """A submitted media item for deepfake analysis."""

    id: str = ""
    file_name: str = ""
    file_size_bytes: int = 0
    media_type: MediaType = MediaType.IMAGE
    mime_type: str = ""
    sha256: str = ""
    submitted_by: str = ""
    submitted_at: float = 0.0
    source_url: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ArtifactAnalysis(BaseModel):
    """Forensic artifact analysis results for a media item."""

    media_id: str = ""
    media_type: MediaType = MediaType.IMAGE
    compression_anomalies: list[str] = Field(default_factory=list)
    frequency_anomalies: list[str] = Field(default_factory=list)
    noise_inconsistencies: list[str] = Field(default_factory=list)
    lighting_inconsistencies: list[str] = Field(default_factory=list)
    temporal_anomalies: list[str] = Field(default_factory=list)
    spectral_anomalies: list[str] = Field(default_factory=list)
    gan_fingerprints: list[str] = Field(default_factory=list)
    diffusion_artifacts: list[str] = Field(default_factory=list)
    facial_landmarks_score: float = 0.0
    lip_sync_score: float = 0.0
    artifact_score: float = 0.0


class ProvenanceRecord(BaseModel):
    """C2PA / provenance verification record for a media item."""

    media_id: str = ""
    has_c2pa_manifest: bool = False
    c2pa_issuer: str = ""
    c2pa_claim_generator: str = ""
    c2pa_actions: list[str] = Field(default_factory=list)
    c2pa_valid_signature: bool = False
    exif_intact: bool = False
    exif_tool_signatures: list[str] = Field(default_factory=list)
    creation_tool: str = ""
    modification_history: list[str] = Field(default_factory=list)
    blockchain_anchors: list[str] = Field(default_factory=list)
    provenance_score: float = 0.0


class AuthenticityClassification(BaseModel):
    """Final authenticity classification for a media item."""

    media_id: str = ""
    verdict: AuthenticityVerdict = AuthenticityVerdict.UNCERTAIN
    confidence_score: float = 0.0
    artifact_score: float = 0.0
    provenance_score: float = 0.0
    combined_score: float = 0.0
    generation_model_guess: str = ""
    manipulation_techniques: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    llm_reasoning: str = ""


class EvidencePackage(BaseModel):
    """Forensic evidence package for a detection result."""

    media_id: str = ""
    evidence_id: str = ""
    summary: str = ""
    key_indicators: list[str] = Field(default_factory=list)
    forensic_hashes: list[str] = Field(default_factory=list)
    chain_of_custody: list[str] = Field(default_factory=list)
    exportable: bool = True


class DeepfakeDetectorState(BaseModel):
    """Full state for the Deepfake Detector agent."""

    request_id: str = ""
    stage: DetectionStage = DetectionStage.INGEST_MEDIA
    tenant_id: str = ""
    submissions: list[dict[str, Any]] = Field(default_factory=list)
    media_count: int = 0
    artifact_analyses: list[dict[str, Any]] = Field(default_factory=list)
    provenance_records: list[dict[str, Any]] = Field(default_factory=list)
    classifications: list[dict[str, Any]] = Field(default_factory=list)
    evidence_packages: list[dict[str, Any]] = Field(default_factory=list)
    synthetic_rate: float = 0.0
    avg_confidence: float = 0.0
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
