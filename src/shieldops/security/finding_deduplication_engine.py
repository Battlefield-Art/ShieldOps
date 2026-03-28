"""FindingDeduplicationEngine — deduplicate findings."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DedupMethod(StrEnum):
    EXACT_HASH = "exact_hash"
    FUZZY_MATCH = "fuzzy_match"
    SEMANTIC = "semantic"


class MatchConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MergeAction(StrEnum):
    MERGE = "merge"
    KEEP_BOTH = "keep_both"
    DISCARD_DUPLICATE = "discard_duplicate"


# --- Models ---


class DeduplicationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    dedup_method: DedupMethod = DedupMethod.EXACT_HASH
    match_confidence: MatchConfidence = MatchConfidence.HIGH
    merge_action: MergeAction = MergeAction.DISCARD_DUPLICATE
    score: float = 0.0
    finding_hash: str = ""
    duplicate_count: int = 0
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class DeduplicationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    dedup_method: DedupMethod = DedupMethod.EXACT_HASH
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DeduplicationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_dedup_method: dict[str, int] = Field(default_factory=dict)
    by_match_confidence: dict[str, int] = Field(default_factory=dict)
    by_merge_action: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class FindingDeduplicationEngine:
    """Deduplicate security findings."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[DeduplicationRecord] = []
        self._analyses: list[DeduplicationAnalysis] = []
        logger.info(
            "finding_deduplication_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        name: str,
        dedup_method: DedupMethod = (DedupMethod.EXACT_HASH),
        match_confidence: MatchConfidence = (MatchConfidence.HIGH),
        merge_action: MergeAction = (MergeAction.DISCARD_DUPLICATE),
        score: float = 0.0,
        finding_hash: str = "",
        duplicate_count: int = 0,
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> DeduplicationRecord:
        record = DeduplicationRecord(
            name=name,
            dedup_method=dedup_method,
            match_confidence=match_confidence,
            merge_action=merge_action,
            score=score,
            finding_hash=finding_hash,
            duplicate_count=duplicate_count,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "finding_deduplication.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> DeduplicationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        dedup_method: DedupMethod | None = None,
        limit: int = 50,
    ) -> list[DeduplicationRecord]:
        results = list(self._records)
        if dedup_method is not None:
            results = [r for r in results if r.dedup_method == dedup_method]
        return results[-limit:]

    # -- domain methods ---

    def deduplicate(self) -> list[dict[str, Any]]:
        """Group findings by hash for dedup."""
        hash_groups: dict[str, list[DeduplicationRecord]] = {}
        for r in self._records:
            if r.finding_hash:
                hash_groups.setdefault(r.finding_hash, []).append(r)
        results: list[dict[str, Any]] = []
        for h, recs in hash_groups.items():
            if len(recs) > 1:
                results.append(
                    {
                        "hash": h,
                        "count": len(recs),
                        "names": [r.name for r in recs],
                        "action": recs[-1].merge_action.value,
                    }
                )
        return sorted(
            results,
            key=lambda x: x["count"],
            reverse=True,
        )

    def calculate_similarity(
        self,
    ) -> dict[str, Any]:
        """Calculate similarity stats."""
        if not self._records:
            return {"total": 0, "avg_score": 0.0}
        scores = [r.score for r in self._records]
        return {
            "total": len(scores),
            "avg_score": round(sum(scores) / len(scores), 2),
            "high_confidence": sum(
                1 for r in self._records if r.match_confidence == MatchConfidence.HIGH
            ),
            "duplicates_found": sum(r.duplicate_count for r in self._records),
        }

    def merge_findings(
        self,
    ) -> list[dict[str, Any]]:
        """Determine merge actions for duplicates."""
        action_groups: dict[str, int] = {}
        for r in self._records:
            k = r.merge_action.value
            action_groups[k] = action_groups.get(k, 0) + 1
        results: list[dict[str, Any]] = []
        for action, count in action_groups.items():
            results.append({"action": action, "count": count})
        return sorted(
            results,
            key=lambda x: x["count"],
            reverse=True,
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
        }

    def generate_report(
        self,
    ) -> DeduplicationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.dedup_method.value] = by_e1.get(r.dedup_method.value, 0) + 1
            by_e2[r.match_confidence.value] = by_e2.get(r.match_confidence.value, 0) + 1
            by_e3[r.merge_action.value] = by_e3.get(r.merge_action.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gaps = [r.name for r in self._records if r.score < self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Deduplication is healthy")
        return DeduplicationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_dedup_method=by_e1,
            by_match_confidence=by_e2,
            by_merge_action=by_e3,
            top_gaps=gaps,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.dedup_method.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "method_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("finding_deduplication_engine.cleared")
        return {"status": "cleared"}
