"""Model Provenance Tracker Engine — verify and track ML model provenance and integrity."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ArtifactType(StrEnum):
    MODEL_WEIGHTS = "model_weights"
    TOKENIZER = "tokenizer"
    EMBEDDING = "embedding"
    FINE_TUNE = "fine_tune"
    ADAPTER = "adapter"
    CONFIG = "config"


class VerificationStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    TAMPERED = "tampered"
    EXPIRED = "expired"
    PENDING = "pending"


class RegistrySource(StrEnum):
    HUGGINGFACE = "huggingface"
    AWS_SAGEMAKER = "aws_sagemaker"
    GCP_VERTEX = "gcp_vertex"
    AZURE_ML = "azure_ml"
    INTERNAL = "internal"
    CUSTOM = "custom"


# --- Models ---


class ProvenanceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    artifact_name: str = ""
    artifact_type: ArtifactType = ArtifactType.MODEL_WEIGHTS
    registry_source: RegistrySource = RegistrySource.INTERNAL
    verification_status: VerificationStatus = VerificationStatus.PENDING
    hash_digest: str = ""
    origin_url: str = ""
    last_verified: float = 0.0
    risk_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ProvenanceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    artifact_name: str = ""
    artifact_type: ArtifactType = ArtifactType.MODEL_WEIGHTS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ProvenanceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    unverified_count: int = 0
    tampered_count: int = 0
    avg_risk_score: float = 0.0
    by_artifact_type: dict[str, int] = Field(default_factory=dict)
    by_registry: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    top_risks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ModelProvenanceTrackerEngine:
    """Verify and track ML model provenance and integrity across registries."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._risk_threshold = risk_threshold
        self._records: list[ProvenanceRecord] = []
        self._analyses: list[ProvenanceAnalysis] = []
        logger.info(
            "model_provenance_tracker_engine.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        artifact_name: str,
        artifact_type: ArtifactType = ArtifactType.MODEL_WEIGHTS,
        registry_source: RegistrySource = RegistrySource.INTERNAL,
        verification_status: VerificationStatus = VerificationStatus.PENDING,
        hash_digest: str = "",
        origin_url: str = "",
        risk_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ProvenanceRecord:
        record = ProvenanceRecord(
            artifact_name=artifact_name,
            artifact_type=artifact_type,
            registry_source=registry_source,
            verification_status=verification_status,
            hash_digest=hash_digest,
            origin_url=origin_url,
            last_verified=time.time(),
            risk_score=risk_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "model_provenance_tracker_engine.record_added",
            record_id=record.id,
            artifact_name=artifact_name,
            artifact_type=artifact_type.value,
            verification_status=verification_status.value,
        )
        return record

    def get_record(self, record_id: str) -> ProvenanceRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        artifact_type: ArtifactType | None = None,
        verification_status: VerificationStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ProvenanceRecord]:
        results = list(self._records)
        if artifact_type is not None:
            results = [r for r in results if r.artifact_type == artifact_type]
        if verification_status is not None:
            results = [r for r in results if r.verification_status == verification_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        artifact_name: str,
        artifact_type: ArtifactType = ArtifactType.MODEL_WEIGHTS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ProvenanceAnalysis:
        analysis = ProvenanceAnalysis(
            artifact_name=artifact_name,
            artifact_type=artifact_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "model_provenance_tracker_engine.analysis_added",
            artifact_name=artifact_name,
            artifact_type=artifact_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_registry_distribution(self) -> dict[str, Any]:
        """Analyze distribution of artifacts across registries."""
        registry_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.registry_source.value
            registry_data.setdefault(key, []).append(r.risk_score)
        result: dict[str, Any] = {}
        for k, scores in registry_data.items():
            result[k] = {
                "count": len(scores),
                "avg_risk_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_unverified_artifacts(self) -> list[dict[str, Any]]:
        """Identify unverified or tampered artifacts requiring attention."""
        flagged: list[dict[str, Any]] = []
        for r in self._records:
            if r.verification_status in (
                VerificationStatus.UNVERIFIED,
                VerificationStatus.TAMPERED,
            ):
                flagged.append(
                    {
                        "record_id": r.id,
                        "artifact_name": r.artifact_name,
                        "artifact_type": r.artifact_type.value,
                        "registry_source": r.registry_source.value,
                        "verification_status": r.verification_status.value,
                        "risk_score": r.risk_score,
                        "service": r.service,
                    }
                )
        return sorted(flagged, key=lambda x: x["risk_score"], reverse=True)

    def detect_integrity_trends(self) -> list[dict[str, Any]]:
        """Detect trends in model integrity across registries."""
        registry_records: dict[str, list[ProvenanceRecord]] = {}
        for r in self._records:
            registry_records.setdefault(r.registry_source.value, []).append(r)
        trends: list[dict[str, Any]] = []
        for reg, records in registry_records.items():
            tampered = sum(
                1 for r in records if r.verification_status == VerificationStatus.TAMPERED
            )
            risk_scores = [r.risk_score for r in records]
            avg_risk = round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0.0
            trends.append(
                {
                    "registry": reg,
                    "total_artifacts": len(records),
                    "tampered_count": tampered,
                    "avg_risk_score": avg_risk,
                    "trend": ("degrading" if tampered > len(records) * 0.2 else "stable"),
                }
            )
        return sorted(trends, key=lambda x: x["tampered_count"], reverse=True)

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.artifact_name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.risk_score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_risk_score": avg,
            "above_threshold": sum(1 for s in scores if s >= self._risk_threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> ProvenanceReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.artifact_type.value] = by_e1.get(r.artifact_type.value, 0) + 1
            by_e2[r.registry_source.value] = by_e2.get(r.registry_source.value, 0) + 1
            by_e3[r.verification_status.value] = by_e3.get(r.verification_status.value, 0) + 1
        unverified_count = sum(
            1 for r in self._records if r.verification_status == VerificationStatus.UNVERIFIED
        )
        tampered_count = sum(
            1 for r in self._records if r.verification_status == VerificationStatus.TAMPERED
        )
        scores = [r.risk_score for r in self._records]
        avg_risk = round(sum(scores) / len(scores), 2) if scores else 0.0
        flagged = self.identify_unverified_artifacts()
        top_risks = [o["artifact_name"] for o in flagged[:5]]
        recs: list[str] = []
        if self._records and tampered_count > 0:
            recs.append(f"{tampered_count} tampered artifact(s) require immediate review")
        if self._records and unverified_count > 0:
            recs.append(f"{unverified_count} unverified artifact(s) pending verification")
        if self._records and avg_risk >= self._risk_threshold:
            recs.append(f"Avg risk score {avg_risk} at/above threshold ({self._risk_threshold})")
        if not recs:
            recs.append("Model Provenance Tracker Engine is healthy")
        return ProvenanceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            unverified_count=unverified_count,
            tampered_count=tampered_count,
            avg_risk_score=avg_risk,
            by_artifact_type=by_e1,
            by_registry=by_e2,
            by_status=by_e3,
            top_risks=top_risks,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("model_provenance_tracker_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.artifact_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "risk_threshold": self._risk_threshold,
            "artifact_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
