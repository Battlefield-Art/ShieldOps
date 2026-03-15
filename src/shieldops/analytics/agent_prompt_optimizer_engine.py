"""AgentPromptOptimizerEngine — Optimize agent prompts based on outcome quality."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PromptVariant(StrEnum):
    BASELINE = "baseline"
    CANDIDATE_A = "candidate_a"
    CANDIDATE_B = "candidate_b"
    CHAMPION = "champion"


class OptimizationMetric(StrEnum):
    ACCURACY = "accuracy"
    LATENCY = "latency"
    TOKEN_COST = "token_cost"
    USER_SATISFACTION = "user_satisfaction"


class PromptStatus(StrEnum):
    TESTING = "testing"
    CHAMPION = "champion"
    RETIRED = "retired"


# --- Models ---


class AgentPromptOptimizerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    prompt_variant: PromptVariant = PromptVariant.BASELINE
    optimization_metric: OptimizationMetric = OptimizationMetric.ACCURACY
    prompt_status: PromptStatus = PromptStatus.TESTING
    score: float = 0.0
    metric_value: float = 0.0
    token_count: int = 0
    invocation_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentPromptOptimizerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    prompt_variant: PromptVariant = PromptVariant.BASELINE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentPromptOptimizerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_prompt_variant: dict[str, int] = Field(default_factory=dict)
    by_optimization_metric: dict[str, int] = Field(default_factory=dict)
    by_prompt_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentPromptOptimizerEngine:
    """Optimize agent prompts based on outcome quality engine."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AgentPromptOptimizerRecord] = []
        self._analyses: list[AgentPromptOptimizerAnalysis] = []
        logger.info(
            "agent_prompt_optimizer_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        prompt_variant: PromptVariant = PromptVariant.BASELINE,
        optimization_metric: OptimizationMetric = OptimizationMetric.ACCURACY,
        prompt_status: PromptStatus = PromptStatus.TESTING,
        score: float = 0.0,
        metric_value: float = 0.0,
        token_count: int = 0,
        invocation_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> AgentPromptOptimizerRecord:
        record = AgentPromptOptimizerRecord(
            name=name,
            prompt_variant=prompt_variant,
            optimization_metric=optimization_metric,
            prompt_status=prompt_status,
            score=score,
            metric_value=metric_value,
            token_count=token_count,
            invocation_count=invocation_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_prompt_optimizer_engine.record_added",
            record_id=record.id,
            name=name,
            prompt_variant=prompt_variant.value,
            optimization_metric=optimization_metric.value,
        )
        return record

    def get_record(self, record_id: str) -> AgentPromptOptimizerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        prompt_variant: PromptVariant | None = None,
        prompt_status: PromptStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AgentPromptOptimizerRecord]:
        results = list(self._records)
        if prompt_variant is not None:
            results = [r for r in results if r.prompt_variant == prompt_variant]
        if prompt_status is not None:
            results = [r for r in results if r.prompt_status == prompt_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        prompt_variant: PromptVariant = PromptVariant.BASELINE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AgentPromptOptimizerAnalysis:
        analysis = AgentPromptOptimizerAnalysis(
            name=name,
            prompt_variant=prompt_variant,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "agent_prompt_optimizer_engine.analysis_added",
            name=name,
            prompt_variant=prompt_variant.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def evaluate_prompt_variants(self) -> list[dict[str, Any]]:
        """Evaluate performance of each prompt variant."""
        variant_data: dict[str, list[AgentPromptOptimizerRecord]] = {}
        for r in self._records:
            variant_data.setdefault(r.prompt_variant.value, []).append(r)
        results: list[dict[str, Any]] = []
        for variant, records in variant_data.items():
            avg_score = round(sum(r.score for r in records) / len(records), 2)
            avg_metric = round(sum(r.metric_value for r in records) / len(records), 4)
            total_tokens = sum(r.token_count for r in records)
            total_invocations = sum(r.invocation_count for r in records)
            results.append(
                {
                    "variant": variant,
                    "avg_score": avg_score,
                    "avg_metric_value": avg_metric,
                    "total_tokens": total_tokens,
                    "total_invocations": total_invocations,
                    "record_count": len(records),
                }
            )
        return sorted(results, key=lambda x: x["avg_score"], reverse=True)

    def identify_winning_prompts(self) -> list[dict[str, Any]]:
        """Identify the best performing prompt per agent/service."""
        svc_variants: dict[str, dict[str, list[AgentPromptOptimizerRecord]]] = {}
        for r in self._records:
            svc_variants.setdefault(r.service, {}).setdefault(r.prompt_variant.value, []).append(r)
        winners: list[dict[str, Any]] = []
        for svc, variants in svc_variants.items():
            best_variant = None
            best_avg = -1.0
            for variant, records in variants.items():
                avg = sum(r.score for r in records) / len(records)
                if avg > best_avg:
                    best_avg = avg
                    best_variant = variant
            if best_variant is not None:
                winners.append(
                    {
                        "service": svc,
                        "winning_variant": best_variant,
                        "avg_score": round(best_avg, 2),
                        "variants_tested": len(variants),
                        "total_records": sum(len(v) for v in variants.values()),
                    }
                )
        return sorted(winners, key=lambda x: x["avg_score"], reverse=True)

    def compute_prompt_roi(self) -> list[dict[str, Any]]:
        """Compute ROI of prompt optimization efforts."""
        svc_data: dict[str, list[AgentPromptOptimizerRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        roi_results: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            baseline = [r for r in records if r.prompt_variant == PromptVariant.BASELINE]
            champion = [r for r in records if r.prompt_variant == PromptVariant.CHAMPION]
            if not baseline or not champion:
                continue
            baseline_avg = sum(r.score for r in baseline) / len(baseline)
            champion_avg = sum(r.score for r in champion) / len(champion)
            improvement = round(champion_avg - baseline_avg, 2)
            baseline_tokens = sum(r.token_count for r in baseline)
            champion_tokens = sum(r.token_count for r in champion)
            token_diff = champion_tokens - baseline_tokens
            roi_results.append(
                {
                    "service": svc,
                    "baseline_avg_score": round(baseline_avg, 2),
                    "champion_avg_score": round(champion_avg, 2),
                    "score_improvement": improvement,
                    "token_cost_change": token_diff,
                    "roi_positive": improvement > 0,
                }
            )
        return sorted(roi_results, key=lambda x: x["score_improvement"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.prompt_variant.value
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
                        "prompt_variant": r.prompt_variant.value,
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

    def generate_report(self) -> AgentPromptOptimizerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.prompt_variant.value] = by_e1.get(r.prompt_variant.value, 0) + 1
            by_e2[r.optimization_metric.value] = by_e2.get(r.optimization_metric.value, 0) + 1
            by_e3[r.prompt_status.value] = by_e3.get(r.prompt_status.value, 0) + 1
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
            recs.append("Agent Prompt Optimizer Engine is healthy")
        return AgentPromptOptimizerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_prompt_variant=by_e1,
            by_optimization_metric=by_e2,
            by_prompt_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_prompt_optimizer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.prompt_variant.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "prompt_variant_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
