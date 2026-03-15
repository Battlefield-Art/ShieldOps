"""TailSamplingPolicyEngine — Manage and optimize tail-based sampling policies."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PolicyDecision(StrEnum):
    ALWAYS_SAMPLE = "always_sample"
    PROBABILISTIC = "probabilistic"
    RATE_LIMIT = "rate_limit"


class SamplingCriteria(StrEnum):
    LATENCY = "latency"
    ERROR = "error"
    ATTRIBUTE = "attribute"
    COMPOSITE = "composite"


class PolicyEffectiveness(StrEnum):
    OPTIMAL = "optimal"
    OVERSAMPLING = "oversampling"
    UNDERSAMPLING = "undersampling"


# --- Models ---


class TailSamplingPolicyRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    policy_decision: PolicyDecision = PolicyDecision.ALWAYS_SAMPLE
    sampling_criteria: SamplingCriteria = SamplingCriteria.LATENCY
    policy_effectiveness: PolicyEffectiveness = PolicyEffectiveness.OPTIMAL
    score: float = 0.0
    sample_rate: float = 1.0
    spans_evaluated: int = 0
    spans_sampled: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class TailSamplingPolicyAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    policy_decision: PolicyDecision = PolicyDecision.ALWAYS_SAMPLE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TailSamplingPolicyReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_policy_decision: dict[str, int] = Field(default_factory=dict)
    by_sampling_criteria: dict[str, int] = Field(default_factory=dict)
    by_policy_effectiveness: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class TailSamplingPolicyEngine:
    """Manage and optimize tail-based sampling policies engine."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[TailSamplingPolicyRecord] = []
        self._analyses: list[TailSamplingPolicyAnalysis] = []
        logger.info(
            "tail_sampling_policy_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        policy_decision: PolicyDecision = PolicyDecision.ALWAYS_SAMPLE,
        sampling_criteria: SamplingCriteria = SamplingCriteria.LATENCY,
        policy_effectiveness: PolicyEffectiveness = PolicyEffectiveness.OPTIMAL,
        score: float = 0.0,
        sample_rate: float = 1.0,
        spans_evaluated: int = 0,
        spans_sampled: int = 0,
        service: str = "",
        team: str = "",
    ) -> TailSamplingPolicyRecord:
        record = TailSamplingPolicyRecord(
            name=name,
            policy_decision=policy_decision,
            sampling_criteria=sampling_criteria,
            policy_effectiveness=policy_effectiveness,
            score=score,
            sample_rate=sample_rate,
            spans_evaluated=spans_evaluated,
            spans_sampled=spans_sampled,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "tail_sampling_policy_engine.record_added",
            record_id=record.id,
            name=name,
            policy_decision=policy_decision.value,
            sampling_criteria=sampling_criteria.value,
        )
        return record

    def get_record(self, record_id: str) -> TailSamplingPolicyRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        policy_decision: PolicyDecision | None = None,
        sampling_criteria: SamplingCriteria | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[TailSamplingPolicyRecord]:
        results = list(self._records)
        if policy_decision is not None:
            results = [r for r in results if r.policy_decision == policy_decision]
        if sampling_criteria is not None:
            results = [r for r in results if r.sampling_criteria == sampling_criteria]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        policy_decision: PolicyDecision = PolicyDecision.ALWAYS_SAMPLE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> TailSamplingPolicyAnalysis:
        analysis = TailSamplingPolicyAnalysis(
            name=name,
            policy_decision=policy_decision,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "tail_sampling_policy_engine.analysis_added",
            name=name,
            policy_decision=policy_decision.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def evaluate_policy_effectiveness(self) -> list[dict[str, Any]]:
        """Evaluate how effective each sampling policy is."""
        policy_stats: dict[str, list[TailSamplingPolicyRecord]] = {}
        for r in self._records:
            policy_stats.setdefault(r.name, []).append(r)
        results: list[dict[str, Any]] = []
        for name, records in policy_stats.items():
            total_evaluated = sum(r.spans_evaluated for r in records)
            total_sampled = sum(r.spans_sampled for r in records)
            actual_rate = round(total_sampled / total_evaluated, 4) if total_evaluated > 0 else 0.0
            avg_score = round(sum(r.score for r in records) / len(records), 2)
            effectiveness_counts: dict[str, int] = {}
            for r in records:
                effectiveness_counts[r.policy_effectiveness.value] = (
                    effectiveness_counts.get(r.policy_effectiveness.value, 0) + 1
                )
            results.append(
                {
                    "policy_name": name,
                    "total_evaluated": total_evaluated,
                    "total_sampled": total_sampled,
                    "actual_sample_rate": actual_rate,
                    "avg_score": avg_score,
                    "effectiveness_distribution": effectiveness_counts,
                    "record_count": len(records),
                }
            )
        return sorted(results, key=lambda x: x["avg_score"])

    def detect_oversampled_services(self) -> list[dict[str, Any]]:
        """Detect services that are being oversampled."""
        svc_data: dict[str, list[TailSamplingPolicyRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        oversampled: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            oversampling_count = sum(
                1 for r in records if r.policy_effectiveness == PolicyEffectiveness.OVERSAMPLING
            )
            if oversampling_count > 0:
                total_evaluated = sum(r.spans_evaluated for r in records)
                total_sampled = sum(r.spans_sampled for r in records)
                oversampled.append(
                    {
                        "service": svc,
                        "oversampling_count": oversampling_count,
                        "total_records": len(records),
                        "oversampling_ratio": round(oversampling_count / len(records), 2),
                        "total_evaluated": total_evaluated,
                        "total_sampled": total_sampled,
                        "recommendation": "reduce_sample_rate",
                    }
                )
        return sorted(oversampled, key=lambda x: x["oversampling_ratio"], reverse=True)

    def recommend_policy_adjustments(self) -> list[dict[str, Any]]:
        """Recommend adjustments to sampling policies."""
        recommendations: list[dict[str, Any]] = []
        for r in self._records:
            if r.policy_effectiveness == PolicyEffectiveness.OVERSAMPLING:
                recommendations.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "issue": "oversampling",
                        "priority": "medium",
                        "suggestion": f"Reduce sample rate from {r.sample_rate} for {r.service}",
                    }
                )
            elif r.policy_effectiveness == PolicyEffectiveness.UNDERSAMPLING:
                recommendations.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "issue": "undersampling",
                        "priority": "high",
                        "suggestion": f"Increase sample rate from {r.sample_rate} for {r.service}",
                    }
                )
            elif r.score < self._threshold:
                recommendations.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "issue": "low_score",
                        "priority": "medium",
                        "suggestion": f"Review policy configuration (score: {r.score})",
                    }
                )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else 1,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.policy_decision.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "policy_decision": r.policy_decision.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> TailSamplingPolicyReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.policy_decision.value] = by_e1.get(r.policy_decision.value, 0) + 1
            by_e2[r.sampling_criteria.value] = by_e2.get(r.sampling_criteria.value, 0) + 1
            by_e3[r.policy_effectiveness.value] = by_e3.get(r.policy_effectiveness.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Tail Sampling Policy Engine is healthy")
        return TailSamplingPolicyReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_policy_decision=by_e1,
            by_sampling_criteria=by_e2,
            by_policy_effectiveness=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("tail_sampling_policy_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.policy_decision.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "policy_decision_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
