"""FindingCorrelationEngine — correlate findings."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CorrelationBasis(StrEnum):
    ASSET = "asset"
    CVE = "cve"
    ATTACK_VECTOR = "attack_vector"
    TEMPORAL = "temporal"


class RelationshipType(StrEnum):
    CAUSAL = "causal"
    COOCCURRENCE = "cooccurrence"
    DEPENDENCY = "dependency"
    ESCALATION = "escalation"


class GroupStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


# --- Models ---


class CorrelationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    correlation_basis: CorrelationBasis = CorrelationBasis.ASSET
    relationship_type: RelationshipType = RelationshipType.COOCCURRENCE
    group_status: GroupStatus = GroupStatus.OPEN
    score: float = 0.0
    finding_ids: list[str] = Field(default_factory=list)
    root_cause_id: str = ""
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CorrelationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    correlation_basis: CorrelationBasis = CorrelationBasis.ASSET
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CorrelationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_correlation_basis: dict[str, int] = Field(default_factory=dict)
    by_relationship_type: dict[str, int] = Field(default_factory=dict)
    by_group_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class FindingCorrelationEngine:
    """Correlate security findings."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[CorrelationRecord] = []
        self._analyses: list[CorrelationAnalysis] = []
        logger.info(
            "finding_correlation_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        name: str,
        correlation_basis: CorrelationBasis = (CorrelationBasis.ASSET),
        relationship_type: RelationshipType = (RelationshipType.COOCCURRENCE),
        group_status: GroupStatus = GroupStatus.OPEN,
        score: float = 0.0,
        finding_ids: list[str] | None = None,
        root_cause_id: str = "",
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> CorrelationRecord:
        record = CorrelationRecord(
            name=name,
            correlation_basis=correlation_basis,
            relationship_type=relationship_type,
            group_status=group_status,
            score=score,
            finding_ids=finding_ids or [],
            root_cause_id=root_cause_id,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "finding_correlation.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> CorrelationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        correlation_basis: (CorrelationBasis | None) = None,
        group_status: GroupStatus | None = None,
        limit: int = 50,
    ) -> list[CorrelationRecord]:
        results = list(self._records)
        if correlation_basis is not None:
            results = [r for r in results if r.correlation_basis == correlation_basis]
        if group_status is not None:
            results = [r for r in results if r.group_status == group_status]
        return results[-limit:]

    # -- domain methods ---

    def correlate_findings(
        self,
    ) -> list[dict[str, Any]]:
        """Group findings by correlation basis."""
        basis_groups: dict[str, list[CorrelationRecord]] = {}
        for r in self._records:
            basis_groups.setdefault(r.correlation_basis.value, []).append(r)
        results: list[dict[str, Any]] = []
        for basis, recs in basis_groups.items():
            results.append(
                {
                    "basis": basis,
                    "group_count": len(recs),
                    "total_findings": sum(len(r.finding_ids) for r in recs),
                    "avg_score": round(
                        sum(r.score for r in recs) / len(recs),
                        2,
                    ),
                }
            )
        return sorted(
            results,
            key=lambda x: x["group_count"],
            reverse=True,
        )

    def build_relationship_graph(
        self,
    ) -> dict[str, Any]:
        """Build a graph of finding relationships."""
        edges: list[dict[str, str]] = []
        for r in self._records:
            for fid in r.finding_ids:
                if r.root_cause_id:
                    edges.append(
                        {
                            "source": (r.root_cause_id),
                            "target": fid,
                            "type": (r.relationship_type.value),
                        }
                    )
        return {
            "nodes": len({e["source"] for e in edges} | {e["target"] for e in edges}),
            "edges": len(edges),
            "edge_list": edges[:100],
        }

    def identify_root_cause(
        self,
    ) -> list[dict[str, Any]]:
        """Identify root causes from correlations."""
        cause_counts: dict[str, int] = {}
        for r in self._records:
            if r.root_cause_id:
                cause_counts[r.root_cause_id] = cause_counts.get(r.root_cause_id, 0) + len(
                    r.finding_ids
                )
        results: list[dict[str, Any]] = []
        for cause, count in cause_counts.items():
            results.append(
                {
                    "root_cause_id": cause,
                    "affected_findings": count,
                }
            )
        return sorted(
            results,
            key=lambda x: x["affected_findings"],
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

    def generate_report(self) -> CorrelationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.correlation_basis.value] = by_e1.get(r.correlation_basis.value, 0) + 1
            by_e2[r.relationship_type.value] = by_e2.get(r.relationship_type.value, 0) + 1
            by_e3[r.group_status.value] = by_e3.get(r.group_status.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gaps = [r.name for r in self._records if r.score < self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Correlation is healthy")
        return CorrelationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_correlation_basis=by_e1,
            by_relationship_type=by_e2,
            by_group_status=by_e3,
            top_gaps=gaps,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.correlation_basis.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "basis_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("finding_correlation_engine.cleared")
        return {"status": "cleared"}
