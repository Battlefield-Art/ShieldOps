"""Attack Path Engine — generate and analyze attack paths."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PathComplexity(StrEnum):
    TRIVIAL = "trivial"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    EXTREME = "extreme"


class NodeType(StrEnum):
    COMPUTE = "compute"
    IDENTITY = "identity"
    STORAGE = "storage"
    NETWORK = "network"
    APPLICATION = "application"


class PathStatus(StrEnum):
    ACTIVE = "active"
    MITIGATED = "mitigated"
    MONITORING = "monitoring"
    ACCEPTED = "accepted"
    BLOCKED = "blocked"


# --- Models ---


class AttackPathRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    path_id: str = ""
    complexity: PathComplexity = PathComplexity.MODERATE
    entry_node_type: NodeType = NodeType.COMPUTE
    target_node_type: NodeType = NodeType.STORAGE
    status: PathStatus = PathStatus.ACTIVE
    hop_count: int = 0
    risk_score: float = 0.0
    chokepoint: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AttackPathAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    path_id: str = ""
    complexity: PathComplexity = PathComplexity.MODERATE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AttackPathReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_risk_score: float = 0.0
    active_paths: int = 0
    by_complexity: dict[str, int] = Field(default_factory=dict)
    by_node_type: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    top_chokepoints: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AttackPathEngine:
    """Generate and analyze attack paths."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._risk_threshold = risk_threshold
        self._records: list[AttackPathRecord] = []
        self._analyses: list[AttackPathAnalysis] = []
        logger.info(
            "attack_path_engine.init",
            max_records=max_records,
        )

    # -- record --

    def add_record(
        self,
        path_id: str = "",
        complexity: PathComplexity = (PathComplexity.MODERATE),
        entry_node_type: NodeType = (NodeType.COMPUTE),
        target_node_type: NodeType = (NodeType.STORAGE),
        status: PathStatus = PathStatus.ACTIVE,
        hop_count: int = 0,
        risk_score: float = 0.0,
        chokepoint: str = "",
        service: str = "",
        team: str = "",
    ) -> AttackPathRecord:
        record = AttackPathRecord(
            path_id=path_id,
            complexity=complexity,
            entry_node_type=entry_node_type,
            target_node_type=target_node_type,
            status=status,
            hop_count=hop_count,
            risk_score=risk_score,
            chokepoint=chokepoint,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "attack_path.record_added",
            record_id=record.id,
        )
        return record

    # -- process --

    def process(self, path_id: str) -> AttackPathAnalysis:
        relevant = [r for r in self._records if r.path_id == path_id]
        if not relevant:
            analysis = AttackPathAnalysis(
                path_id=path_id,
                description="no records found",
            )
            self._analyses.append(analysis)
            return analysis
        scores = [r.risk_score for r in relevant]
        avg = sum(scores) / len(scores)
        breached = avg > self._risk_threshold
        analysis = AttackPathAnalysis(
            path_id=path_id,
            analysis_score=round(avg, 2),
            threshold=self._risk_threshold,
            breached=breached,
            description=(f"avg_risk={round(avg, 2)}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain methods --

    def generate_attack_path(
        self,
    ) -> dict[str, Any]:
        """Paths grouped by entry -> target."""
        path_data: dict[str, int] = {}
        for r in self._records:
            key = f"{r.entry_node_type.value}->{r.target_node_type.value}"
            path_data[key] = path_data.get(key, 0) + 1
        return {"paths": path_data}

    def calculate_path_risk(
        self,
    ) -> list[dict[str, Any]]:
        """Risk by path, sorted descending."""
        path_scores: dict[str, list[float]] = {}
        for r in self._records:
            path_scores.setdefault(r.path_id, []).append(r.risk_score)
        results: list[dict[str, Any]] = []
        for pid, scores in path_scores.items():
            avg = sum(scores) / len(scores)
            results.append(
                {
                    "path_id": pid,
                    "avg_risk": round(avg, 2),
                    "max_risk": round(max(scores), 2),
                    "hops": len(scores),
                }
            )
        return sorted(
            results,
            key=lambda x: x["avg_risk"],
            reverse=True,
        )

    def identify_chokepoints(
        self,
    ) -> list[dict[str, Any]]:
        """Find frequently used chokepoints."""
        choke_counts: dict[str, int] = {}
        for r in self._records:
            if r.chokepoint:
                choke_counts[r.chokepoint] = choke_counts.get(r.chokepoint, 0) + 1
        results: list[dict[str, Any]] = []
        for choke, count in choke_counts.items():
            results.append(
                {
                    "chokepoint": choke,
                    "path_count": count,
                    "priority": ("high" if count > 3 else "medium"),
                }
            )
        return sorted(
            results,
            key=lambda x: x["path_count"],
            reverse=True,
        )

    # -- report / stats --

    def generate_report(
        self,
    ) -> AttackPathReport:
        by_c: dict[str, int] = {}
        by_n: dict[str, int] = {}
        by_s: dict[str, int] = {}
        for r in self._records:
            by_c[r.complexity.value] = by_c.get(r.complexity.value, 0) + 1
            by_n[r.entry_node_type.value] = by_n.get(r.entry_node_type.value, 0) + 1
            by_s[r.status.value] = by_s.get(r.status.value, 0) + 1
        scores = [r.risk_score for r in self._records]
        avg_risk = round(sum(scores) / len(scores), 2) if scores else 0.0
        active = sum(1 for r in self._records if r.status == PathStatus.ACTIVE)
        chokes = self.identify_chokepoints()
        top_chokes = [c["chokepoint"] for c in chokes[:5]]
        recs: list[str] = []
        if active > 0:
            recs.append(f"{active} active attack paths")
        high_risk = sum(1 for r in self._records if r.risk_score > self._risk_threshold)
        if high_risk > 0:
            recs.append(f"{high_risk} paths above risk threshold")
        if not recs:
            recs.append("Attack path posture healthy")
        return AttackPathReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_risk_score=avg_risk,
            active_paths=active,
            by_complexity=by_c,
            by_node_type=by_n,
            by_status=by_s,
            top_chokepoints=top_chokes,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "risk_threshold": (self._risk_threshold),
            "unique_paths": len({r.path_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("attack_path_engine.cleared")
        return {"status": "cleared"}
