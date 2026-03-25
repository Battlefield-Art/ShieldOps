"""Kill Chain Reconstructor Engine — track and analyze kill chain reconstruction accuracy."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class KillChainModel(StrEnum):
    CYBER_KILL_CHAIN = "cyber_kill_chain"
    MITRE_ATTCK = "mitre_attck"
    DIAMOND = "diamond"
    UNIFIED = "unified"


class ReconstructionAccuracy(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FRAGMENTED = "fragmented"
    MINIMAL = "minimal"
    FAILED = "failed"


class AttackStage(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    C2 = "c2"
    EXFILTRATION = "exfiltration"


# --- Models ---


class ReconstructionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    kill_chain_model: KillChainModel = KillChainModel.CYBER_KILL_CHAIN
    reconstruction_accuracy: ReconstructionAccuracy = ReconstructionAccuracy.COMPLETE
    stages_identified: int = 0
    total_stages: int = 7
    confidence: float = 0.0
    time_to_reconstruct_ms: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ReconstructionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    kill_chain_model: KillChainModel = KillChainModel.CYBER_KILL_CHAIN
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ReconstructionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    incomplete_count: int = 0
    avg_confidence: float = 0.0
    by_model: dict[str, int] = Field(default_factory=dict)
    by_accuracy: dict[str, int] = Field(default_factory=dict)
    by_stage: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class KillChainReconstructorEngine:
    """Track and analyze kill chain reconstruction accuracy."""

    def __init__(
        self,
        max_records: int = 200000,
        accuracy_threshold: float = 75.0,
    ) -> None:
        self._max_records = max_records
        self._accuracy_threshold = accuracy_threshold
        self._records: list[ReconstructionRecord] = []
        self._analyses: list[ReconstructionAnalysis] = []
        logger.info(
            "kill_chain_reconstructor_engine.initialized",
            max_records=max_records,
            accuracy_threshold=accuracy_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        incident_id: str,
        kill_chain_model: KillChainModel = KillChainModel.CYBER_KILL_CHAIN,
        reconstruction_accuracy: ReconstructionAccuracy = ReconstructionAccuracy.COMPLETE,
        stages_identified: int = 0,
        total_stages: int = 7,
        confidence: float = 0.0,
        time_to_reconstruct_ms: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ReconstructionRecord:
        record = ReconstructionRecord(
            incident_id=incident_id,
            kill_chain_model=kill_chain_model,
            reconstruction_accuracy=reconstruction_accuracy,
            stages_identified=stages_identified,
            total_stages=total_stages,
            confidence=confidence,
            time_to_reconstruct_ms=time_to_reconstruct_ms,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "kill_chain_reconstructor_engine.record_added",
            record_id=record.id,
            incident_id=incident_id,
            reconstruction_accuracy=reconstruction_accuracy.value,
        )
        return record

    def get_record(self, record_id: str) -> ReconstructionRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        kill_chain_model: KillChainModel | None = None,
        reconstruction_accuracy: ReconstructionAccuracy | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ReconstructionRecord]:
        results = list(self._records)
        if kill_chain_model is not None:
            results = [r for r in results if r.kill_chain_model == kill_chain_model]
        if reconstruction_accuracy is not None:
            results = [r for r in results if r.reconstruction_accuracy == reconstruction_accuracy]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        incident_id: str,
        kill_chain_model: KillChainModel = KillChainModel.CYBER_KILL_CHAIN,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ReconstructionAnalysis:
        analysis = ReconstructionAnalysis(
            incident_id=incident_id,
            kill_chain_model=kill_chain_model,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "kill_chain_reconstructor_engine.analysis_added",
            incident_id=incident_id,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_reconstruction_quality(self) -> dict[str, Any]:
        """Group by kill_chain_model; return count and avg confidence."""
        model_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.kill_chain_model.value
            model_data.setdefault(key, []).append(r.confidence)
        result: dict[str, Any] = {}
        for model, confs in model_data.items():
            result[model] = {
                "count": len(confs),
                "avg_confidence": round(sum(confs) / len(confs), 2),
            }
        return result

    def identify_chain_gaps(self) -> list[dict[str, Any]]:
        """Return records where confidence < accuracy_threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.confidence < self._accuracy_threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "incident_id": r.incident_id,
                        "kill_chain_model": r.kill_chain_model.value,
                        "stages_identified": r.stages_identified,
                        "total_stages": r.total_stages,
                        "confidence": r.confidence,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["confidence"])

    def detect_reconstruction_trends(self) -> dict[str, Any]:
        """Split-half comparison on analysis_score; delta threshold 5.0."""
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [c.analysis_score for c in self._analyses]
        mid = len(vals) // 2
        first_half = vals[:mid]
        second_half = vals[mid:]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        delta = round(avg_second - avg_first, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "avg_first_half": round(avg_first, 2),
            "avg_second_half": round(avg_second, 2),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> ReconstructionReport:
        by_model: dict[str, int] = {}
        by_accuracy: dict[str, int] = {}
        by_stage: dict[str, int] = {}
        for r in self._records:
            by_model[r.kill_chain_model.value] = by_model.get(r.kill_chain_model.value, 0) + 1
            by_accuracy[r.reconstruction_accuracy.value] = (
                by_accuracy.get(r.reconstruction_accuracy.value, 0) + 1
            )
        incomplete_count = sum(1 for r in self._records if r.confidence < self._accuracy_threshold)
        confs = [r.confidence for r in self._records]
        avg_confidence = round(sum(confs) / len(confs), 2) if confs else 0.0
        gap_list = self.identify_chain_gaps()
        top_gaps = [g["incident_id"] for g in gap_list[:5]]
        recs: list[str] = []
        if incomplete_count > 0:
            recs.append(
                f"{incomplete_count} reconstruction(s) below accuracy threshold "
                f"({self._accuracy_threshold}%)"
            )
        if avg_confidence < self._accuracy_threshold:
            recs.append(
                f"Avg confidence {avg_confidence}% below threshold ({self._accuracy_threshold}%)"
            )
        if not recs:
            recs.append("Kill chain reconstruction accuracy is healthy")
        return ReconstructionReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            incomplete_count=incomplete_count,
            avg_confidence=avg_confidence,
            by_model=by_model,
            by_accuracy=by_accuracy,
            by_stage=by_stage,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("kill_chain_reconstructor_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        model_dist: dict[str, int] = {}
        for r in self._records:
            key = r.kill_chain_model.value
            model_dist[key] = model_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "accuracy_threshold": self._accuracy_threshold,
            "model_distribution": model_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
