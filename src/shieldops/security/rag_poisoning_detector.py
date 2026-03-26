"""RAG Poisoning Detector — detect poisoned RAG documents."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PoisonType(StrEnum):
    ADVERSARIAL_EMBEDDING = "adversarial_embedding"
    DOCUMENT_INJECTION = "document_injection"
    CONTEXT_MANIPULATION = "context_manipulation"


class DetectionMethod(StrEnum):
    EMBEDDING_ANALYSIS = "embedding_analysis"
    CONTENT_SCAN = "content_scan"
    BEHAVIORAL_TEST = "behavioral_test"


class DocumentRisk(StrEnum):
    POISONED = "poisoned"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNSCANNED = "unscanned"


# --- Models ---


class RAGPoisonRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    document_id: str = ""
    collection: str = ""
    poison_type: PoisonType | None = None
    detection_method: DetectionMethod = DetectionMethod.CONTENT_SCAN
    risk_level: DocumentRisk = DocumentRisk.UNSCANNED
    risk_score: float = 0.0
    quarantined: bool = False
    details: str = ""
    created_at: float = Field(default_factory=time.time)


class RAGPoisonAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    collection: str = ""
    total_scanned: int = 0
    poisoned_count: int = 0
    suspicious_count: int = 0
    clean_count: int = 0
    quarantined_count: int = 0
    avg_risk: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class RAGPoisonReport(BaseModel):
    total_documents: int = 0
    by_risk: dict[str, int] = Field(default_factory=dict)
    by_poison_type: dict[str, int] = Field(default_factory=dict)
    by_method: dict[str, int] = Field(default_factory=dict)
    quarantined_count: int = 0
    avg_risk_score: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class RAGPoisoningDetectorEngine:
    """Detect poisoned documents in RAG pipelines."""

    def __init__(
        self,
        max_records: int = 200000,
        poison_threshold: float = 0.7,
    ) -> None:
        self._max_records = max_records
        self._poison_threshold = poison_threshold
        self._records: list[RAGPoisonRecord] = []
        logger.info(
            "rag_poisoning_detector.initialized",
            max_records=max_records,
            poison_threshold=poison_threshold,
        )

    def _score_to_risk(self, score: float) -> DocumentRisk:
        if score >= self._poison_threshold:
            return DocumentRisk.POISONED
        if score >= 0.4:
            return DocumentRisk.SUSPICIOUS
        return DocumentRisk.CLEAN

    # -- record / query --

    def add_record(
        self,
        document_id: str,
        collection: str = "",
        poison_type: PoisonType | None = None,
        detection_method: DetectionMethod = (DetectionMethod.CONTENT_SCAN),
        risk_score: float = 0.0,
        details: str = "",
    ) -> RAGPoisonRecord:
        risk_level = self._score_to_risk(risk_score)
        record = RAGPoisonRecord(
            document_id=document_id,
            collection=collection,
            poison_type=poison_type,
            detection_method=detection_method,
            risk_level=risk_level,
            risk_score=risk_score,
            details=details,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "rag_poisoning_detector.record_added",
            record_id=record.id,
            document_id=document_id,
            risk_level=risk_level.value,
        )
        return record

    def process(self, collection: str) -> RAGPoisonAnalysis:
        docs = [r for r in self._records if r.collection == collection]
        if not docs:
            return RAGPoisonAnalysis(collection=collection)
        poisoned = sum(1 for d in docs if d.risk_level == DocumentRisk.POISONED)
        suspicious = sum(1 for d in docs if d.risk_level == DocumentRisk.SUSPICIOUS)
        clean = sum(1 for d in docs if d.risk_level == DocumentRisk.CLEAN)
        quarantined = sum(1 for d in docs if d.quarantined)
        avg_risk = round(
            sum(d.risk_score for d in docs) / len(docs),
            4,
        )
        return RAGPoisonAnalysis(
            collection=collection,
            total_scanned=len(docs),
            poisoned_count=poisoned,
            suspicious_count=suspicious,
            clean_count=clean,
            quarantined_count=quarantined,
            avg_risk=avg_risk,
        )

    def generate_report(self) -> RAGPoisonReport:
        by_risk: dict[str, int] = {}
        by_poison: dict[str, int] = {}
        by_method: dict[str, int] = {}
        for r in self._records:
            by_risk[r.risk_level.value] = by_risk.get(r.risk_level.value, 0) + 1
            if r.poison_type:
                key = r.poison_type.value
                by_poison[key] = by_poison.get(key, 0) + 1
            by_method[r.detection_method.value] = by_method.get(r.detection_method.value, 0) + 1
        total = len(self._records)
        quarantined = sum(1 for r in self._records if r.quarantined)
        avg_risk = (
            round(
                sum(r.risk_score for r in self._records) / total,
                4,
            )
            if total
            else 0.0
        )
        recs: list[str] = []
        poisoned_ct = by_risk.get(DocumentRisk.POISONED.value, 0)
        if poisoned_ct > 0:
            recs.append(f"{poisoned_ct} poisoned document(s) detected")
        suspicious_ct = by_risk.get(DocumentRisk.SUSPICIOUS.value, 0)
        if suspicious_ct > 0:
            recs.append(f"{suspicious_ct} suspicious document(s) require review")
        unscanned = by_risk.get(DocumentRisk.UNSCANNED.value, 0)
        if unscanned > 0:
            recs.append(f"{unscanned} document(s) unscanned")
        if not recs:
            recs.append("RAG corpus appears clean")
        return RAGPoisonReport(
            total_documents=total,
            by_risk=by_risk,
            by_poison_type=by_poison,
            by_method=by_method,
            quarantined_count=quarantined,
            avg_risk_score=avg_risk,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        risk_dist: dict[str, int] = {}
        for r in self._records:
            key = r.risk_level.value
            risk_dist[key] = risk_dist.get(key, 0) + 1
        return {
            "total_documents": len(self._records),
            "max_records": self._max_records,
            "poison_threshold": self._poison_threshold,
            "risk_distribution": risk_dist,
            "quarantined": sum(1 for r in self._records if r.quarantined),
            "unique_collections": len({r.collection for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("rag_poisoning_detector.cleared")
        return {"status": "cleared"}

    # -- domain operations --

    def scan_rag_documents(
        self,
        document_ids: list[str],
        collection: str = "",
        method: DetectionMethod = (DetectionMethod.CONTENT_SCAN),
    ) -> dict[str, Any]:
        """Scan a batch of RAG documents."""
        results: list[dict[str, Any]] = []
        for doc_id in document_ids:
            # Simulate scan with heuristic score
            score = 0.1  # baseline clean
            record = self.add_record(
                document_id=doc_id,
                collection=collection,
                detection_method=method,
                risk_score=score,
            )
            results.append(
                {
                    "document_id": doc_id,
                    "risk_level": record.risk_level.value,
                    "risk_score": record.risk_score,
                }
            )
        logger.info(
            "rag_poisoning_detector.batch_scanned",
            count=len(document_ids),
            collection=collection,
        )
        return {
            "scanned": len(results),
            "collection": collection,
            "method": method.value,
            "results": results,
        }

    def detect_adversarial_embeddings(
        self,
        document_id: str,
        embedding_distance: float = 0.0,
        cluster_outlier: bool = False,
        collection: str = "",
    ) -> dict[str, Any]:
        """Detect adversarial embeddings."""
        score = 0.0
        if embedding_distance > 0.8:
            score = min(embedding_distance, 1.0)
        if cluster_outlier:
            score = max(score, 0.6)
        poison_type = PoisonType.ADVERSARIAL_EMBEDDING if score >= self._poison_threshold else None
        record = self.add_record(
            document_id=document_id,
            collection=collection,
            poison_type=poison_type,
            detection_method=(DetectionMethod.EMBEDDING_ANALYSIS),
            risk_score=score,
            details=(f"distance={embedding_distance}, outlier={cluster_outlier}"),
        )
        return {
            "record_id": record.id,
            "document_id": document_id,
            "is_adversarial": poison_type is not None,
            "embedding_distance": embedding_distance,
            "cluster_outlier": cluster_outlier,
            "risk_score": score,
            "risk_level": record.risk_level.value,
        }

    def quarantine_poisoned(
        self,
        document_id: str | None = None,
        collection: str | None = None,
    ) -> dict[str, Any]:
        """Quarantine poisoned documents."""
        targets = self._records
        if document_id:
            targets = [r for r in targets if r.document_id == document_id]
        if collection:
            targets = [r for r in targets if r.collection == collection]
        quarantined = 0
        for r in targets:
            if r.risk_level == DocumentRisk.POISONED and not r.quarantined:
                r.quarantined = True
                quarantined += 1
        logger.info(
            "rag_poisoning_detector.quarantined",
            count=quarantined,
        )
        return {
            "quarantined": quarantined,
            "document_id": document_id,
            "collection": collection,
        }
