"""Agent Knowledge Distillation Engine — distill expert agent knowledge into smaller agents."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DistillationMethod(StrEnum):
    RESPONSE_MATCHING = "response_matching"
    FEATURE_TRANSFER = "feature_transfer"
    BEHAVIOR_CLONING = "behavior_cloning"
    ENSEMBLE_AVERAGING = "ensemble_averaging"


class KnowledgeType(StrEnum):
    INVESTIGATION_PATTERNS = "investigation_patterns"
    REMEDIATION_STRATEGIES = "remediation_strategies"
    THREAT_SIGNATURES = "threat_signatures"
    ROUTING_RULES = "routing_rules"


class TransferOutcome(StrEnum):
    SUCCESSFUL = "successful"
    PARTIAL = "partial"
    FAILED = "failed"
    REGRESSED = "regressed"


# --- Models ---


class DistillationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    distillation_method: DistillationMethod = DistillationMethod.RESPONSE_MATCHING
    knowledge_type: KnowledgeType = KnowledgeType.INVESTIGATION_PATTERNS
    transfer_outcome: TransferOutcome = TransferOutcome.SUCCESSFUL
    score: float = 0.0
    expert_agent: str = ""
    student_agent: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class DistillationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    distillation_method: DistillationMethod = DistillationMethod.RESPONSE_MATCHING
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DistillationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_method: dict[str, int] = Field(default_factory=dict)
    by_knowledge_type: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentKnowledgeDistillationEngine:
    """Track and optimize knowledge distillation from expert to student agents."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[DistillationRecord] = []
        self._analyses: list[DistillationAnalysis] = []
        logger.info(
            "agent_knowledge_distillation_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        distillation_method: DistillationMethod = DistillationMethod.RESPONSE_MATCHING,
        knowledge_type: KnowledgeType = KnowledgeType.INVESTIGATION_PATTERNS,
        transfer_outcome: TransferOutcome = TransferOutcome.SUCCESSFUL,
        score: float = 0.0,
        expert_agent: str = "",
        student_agent: str = "",
        service: str = "",
        team: str = "",
    ) -> DistillationRecord:
        record = DistillationRecord(
            name=name,
            distillation_method=distillation_method,
            knowledge_type=knowledge_type,
            transfer_outcome=transfer_outcome,
            score=score,
            expert_agent=expert_agent,
            student_agent=student_agent,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_knowledge_distillation_engine.record_added",
            record_id=record.id,
            name=name,
            distillation_method=distillation_method.value,
            knowledge_type=knowledge_type.value,
        )
        return record

    def get_record(self, record_id: str) -> DistillationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        distillation_method: DistillationMethod | None = None,
        knowledge_type: KnowledgeType | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[DistillationRecord]:
        results = list(self._records)
        if distillation_method is not None:
            results = [r for r in results if r.distillation_method == distillation_method]
        if knowledge_type is not None:
            results = [r for r in results if r.knowledge_type == knowledge_type]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        distillation_method: DistillationMethod = DistillationMethod.RESPONSE_MATCHING,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> DistillationAnalysis:
        analysis = DistillationAnalysis(
            name=name,
            distillation_method=distillation_method,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "agent_knowledge_distillation_engine.analysis_added",
            name=name,
            distillation_method=distillation_method.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_distillation_candidates(self) -> list[dict[str, Any]]:
        """Find expert-student pairs with transfer potential based on scores."""
        pair_scores: dict[str, list[float]] = {}
        for r in self._records:
            key = f"{r.expert_agent}->{r.student_agent}"
            pair_scores.setdefault(key, []).append(r.score)
        results: list[dict[str, Any]] = []
        for pair, scores in pair_scores.items():
            avg = round(sum(scores) / len(scores), 2)
            parts = pair.split("->")
            results.append(
                {
                    "expert_agent": parts[0],
                    "student_agent": parts[1],
                    "avg_score": avg,
                    "transfer_count": len(scores),
                    "potential": "high" if avg >= self._threshold else "low",
                }
            )
        results.sort(key=lambda x: x["avg_score"], reverse=True)
        return results

    def measure_transfer_effectiveness(self) -> dict[str, Any]:
        """Compare student performance before/after distillation via outcome distribution."""
        outcome_counts: dict[str, int] = {}
        outcome_scores: dict[str, list[float]] = {}
        for r in self._records:
            key = r.transfer_outcome.value
            outcome_counts[key] = outcome_counts.get(key, 0) + 1
            outcome_scores.setdefault(key, []).append(r.score)
        effectiveness: dict[str, Any] = {}
        for outcome, scores in outcome_scores.items():
            effectiveness[outcome] = {
                "count": outcome_counts[outcome],
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        total = len(self._records)
        success_count = outcome_counts.get("successful", 0)
        success_rate = round(success_count / total * 100, 2) if total else 0.0
        return {
            "total_transfers": total,
            "success_rate": success_rate,
            "by_outcome": effectiveness,
        }

    def recommend_distillation_strategy(self) -> list[dict[str, Any]]:
        """Suggest best distillation method per knowledge type based on historical scores."""
        kt_method_scores: dict[str, dict[str, list[float]]] = {}
        for r in self._records:
            kt = r.knowledge_type.value
            method = r.distillation_method.value
            kt_method_scores.setdefault(kt, {}).setdefault(method, []).append(r.score)
        results: list[dict[str, Any]] = []
        for kt, methods in kt_method_scores.items():
            best_method = ""
            best_avg = -1.0
            for method, scores in methods.items():
                avg = sum(scores) / len(scores)
                if avg > best_avg:
                    best_avg = avg
                    best_method = method
            results.append(
                {
                    "knowledge_type": kt,
                    "recommended_method": best_method,
                    "avg_score": round(best_avg, 2),
                    "sample_size": sum(len(s) for s in methods.values()),
                }
            )
        results.sort(key=lambda x: x["avg_score"], reverse=True)
        return results

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> DistillationReport:
        by_method: dict[str, int] = {}
        by_knowledge_type: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        for r in self._records:
            by_method[r.distillation_method.value] = (
                by_method.get(r.distillation_method.value, 0) + 1
            )
            by_knowledge_type[r.knowledge_type.value] = (
                by_knowledge_type.get(r.knowledge_type.value, 0) + 1
            )
            by_outcome[r.transfer_outcome.value] = by_outcome.get(r.transfer_outcome.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = [r.name for r in self._records if r.score < self._threshold]
        top_gaps = gap_list[:5]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} transfer(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Agent Knowledge Distillation Engine is healthy")
        return DistillationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_method=by_method,
            by_knowledge_type=by_knowledge_type,
            by_outcome=by_outcome,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_knowledge_distillation_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        method_dist: dict[str, int] = {}
        for r in self._records:
            key = r.distillation_method.value
            method_dist[key] = method_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "method_distribution": method_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
