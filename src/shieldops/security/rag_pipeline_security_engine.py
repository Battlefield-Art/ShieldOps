"""RAG Pipeline Security Engine — monitor and protect RAG data pipelines from poisoning."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DataSourceType(StrEnum):
    VECTOR_DB = "vector_db"
    DOCUMENT_STORE = "document_store"
    WEB_SCRAPER = "web_scraper"
    API_FEED = "api_feed"
    FILE_SYSTEM = "file_system"


class PoisoningType(StrEnum):
    DOCUMENT_INJECTION = "document_injection"
    EMBEDDING_MANIPULATION = "embedding_manipulation"
    CONTEXT_POISONING = "context_poisoning"
    BACKDOOR_TRIGGER = "backdoor_trigger"
    ADVERSARIAL_EXAMPLE = "adversarial_example"


class ThreatLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BENIGN = "benign"


# --- Models ---


class PipelineSecurityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_id: str = ""
    data_source_type: DataSourceType = DataSourceType.VECTOR_DB
    poisoning_type: PoisoningType = PoisoningType.DOCUMENT_INJECTION
    threat_level: ThreatLevel = ThreatLevel.LOW
    confidence: float = 0.0
    affected_documents: int = 0
    description: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class PipelineSecurityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_id: str = ""
    data_source_type: DataSourceType = DataSourceType.VECTOR_DB
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PipelineSecurityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    critical_count: int = 0
    avg_confidence: float = 0.0
    by_source_type: dict[str, int] = Field(default_factory=dict)
    by_poisoning_type: dict[str, int] = Field(default_factory=dict)
    by_threat_level: dict[str, int] = Field(default_factory=dict)
    top_threats: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class RAGPipelineSecurityEngine:
    """Monitor and protect RAG data pipelines from poisoning attacks."""

    def __init__(
        self,
        max_records: int = 200000,
        threat_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threat_threshold = threat_threshold
        self._records: list[PipelineSecurityRecord] = []
        self._analyses: list[PipelineSecurityAnalysis] = []
        logger.info(
            "rag_pipeline_security_engine.initialized",
            max_records=max_records,
            threat_threshold=threat_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        pipeline_id: str,
        data_source_type: DataSourceType = DataSourceType.VECTOR_DB,
        poisoning_type: PoisoningType = PoisoningType.DOCUMENT_INJECTION,
        threat_level: ThreatLevel = ThreatLevel.LOW,
        confidence: float = 0.0,
        affected_documents: int = 0,
        description: str = "",
        service: str = "",
        team: str = "",
    ) -> PipelineSecurityRecord:
        record = PipelineSecurityRecord(
            pipeline_id=pipeline_id,
            data_source_type=data_source_type,
            poisoning_type=poisoning_type,
            threat_level=threat_level,
            confidence=confidence,
            affected_documents=affected_documents,
            description=description,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "rag_pipeline_security_engine.record_added",
            record_id=record.id,
            pipeline_id=pipeline_id,
            data_source_type=data_source_type.value,
            threat_level=threat_level.value,
        )
        return record

    def get_record(self, record_id: str) -> PipelineSecurityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        data_source_type: DataSourceType | None = None,
        poisoning_type: PoisoningType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[PipelineSecurityRecord]:
        results = list(self._records)
        if data_source_type is not None:
            results = [r for r in results if r.data_source_type == data_source_type]
        if poisoning_type is not None:
            results = [r for r in results if r.poisoning_type == poisoning_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        pipeline_id: str,
        data_source_type: DataSourceType = DataSourceType.VECTOR_DB,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> PipelineSecurityAnalysis:
        analysis = PipelineSecurityAnalysis(
            pipeline_id=pipeline_id,
            data_source_type=data_source_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "rag_pipeline_security_engine.analysis_added",
            pipeline_id=pipeline_id,
            data_source_type=data_source_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_threat_distribution(self) -> dict[str, Any]:
        """Analyze distribution of threats across data source types."""
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.data_source_type.value
            type_data.setdefault(key, []).append(r.confidence)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_confidence": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_high_risk_pipelines(self) -> list[dict[str, Any]]:
        """Identify pipelines with critical or high threat levels."""
        high_risk: list[dict[str, Any]] = []
        for r in self._records:
            if r.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
                high_risk.append(
                    {
                        "record_id": r.id,
                        "pipeline_id": r.pipeline_id,
                        "data_source_type": r.data_source_type.value,
                        "poisoning_type": r.poisoning_type.value,
                        "threat_level": r.threat_level.value,
                        "confidence": r.confidence,
                        "affected_documents": r.affected_documents,
                        "service": r.service,
                    }
                )
        return sorted(high_risk, key=lambda x: x["confidence"], reverse=True)

    def detect_poisoning_trends(self) -> list[dict[str, Any]]:
        """Detect trends in poisoning attacks across pipelines."""
        pipeline_data: dict[str, list[PipelineSecurityRecord]] = {}
        for r in self._records:
            pipeline_data.setdefault(r.pipeline_id, []).append(r)
        trends: list[dict[str, Any]] = []
        for pid, records in pipeline_data.items():
            critical_count = sum(1 for r in records if r.threat_level == ThreatLevel.CRITICAL)
            confidences = [r.confidence for r in records]
            avg_conf = round(sum(confidences) / len(confidences), 2) if confidences else 0.0
            trends.append(
                {
                    "pipeline_id": pid,
                    "total_events": len(records),
                    "critical_count": critical_count,
                    "avg_confidence": avg_conf,
                    "trend": "escalating" if critical_count > len(records) * 0.3 else "stable",
                }
            )
        return sorted(trends, key=lambda x: x["critical_count"], reverse=True)

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.pipeline_id == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.confidence for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_confidence": avg,
            "above_threshold": sum(1 for s in scores if s >= self._threat_threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> PipelineSecurityReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.data_source_type.value] = by_e1.get(r.data_source_type.value, 0) + 1
            by_e2[r.poisoning_type.value] = by_e2.get(r.poisoning_type.value, 0) + 1
            by_e3[r.threat_level.value] = by_e3.get(r.threat_level.value, 0) + 1
        critical_count = sum(1 for r in self._records if r.threat_level == ThreatLevel.CRITICAL)
        scores = [r.confidence for r in self._records]
        avg_confidence = round(sum(scores) / len(scores), 2) if scores else 0.0
        high_risk = self.identify_high_risk_pipelines()
        top_threats = [o["pipeline_id"] for o in high_risk[:5]]
        recs: list[str] = []
        if self._records and critical_count > 0:
            recs.append(f"{critical_count} critical threat(s) detected across pipelines")
        if self._records and avg_confidence >= self._threat_threshold:
            recs.append(
                f"Avg confidence {avg_confidence} at/above threshold ({self._threat_threshold})"
            )
        if not recs:
            recs.append("RAG Pipeline Security Engine is healthy")
        return PipelineSecurityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            critical_count=critical_count,
            avg_confidence=avg_confidence,
            by_source_type=by_e1,
            by_poisoning_type=by_e2,
            by_threat_level=by_e3,
            top_threats=top_threats,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("rag_pipeline_security_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.data_source_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threat_threshold": self._threat_threshold,
            "source_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
