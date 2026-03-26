"""Agent Learning Analytics — measure agent learning."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class LearningMetric(StrEnum):
    ACCURACY_IMPROVEMENT = "accuracy_improvement"
    FP_REDUCTION = "fp_reduction"
    SPEED_GAIN = "speed_gain"
    COVERAGE_EXPANSION = "coverage_expansion"


class KnowledgeArea(StrEnum):
    DETECTION = "detection"
    TRIAGE = "triage"
    RESPONSE = "response"
    INVESTIGATION = "investigation"


class RetentionRate(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    DECAYED = "decayed"


# --- Models ---


class LearningRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    metric: LearningMetric = LearningMetric.ACCURACY_IMPROVEMENT
    area: KnowledgeArea = KnowledgeArea.DETECTION
    retention: RetentionRate = RetentionRate.HIGH
    baseline_value: float = 0.0
    current_value: float = 0.0
    improvement_pct: float = 0.0
    sample_count: int = 0
    created_at: float = Field(default_factory=time.time)


class LearningAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    total_metrics: int = 0
    avg_improvement: float = 0.0
    strongest_area: str = ""
    weakest_area: str = ""
    overall_retention: str = ""
    analyzed_at: float = Field(default_factory=time.time)


class LearningReport(BaseModel):
    total_records: int = 0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_area: dict[str, int] = Field(default_factory=dict)
    by_retention: dict[str, int] = Field(default_factory=dict)
    avg_improvement_pct: float = 0.0
    decayed_count: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentLearningAnalyticsEngine:
    """Measure and track agent learning progress."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[LearningRecord] = []
        logger.info(
            "agent_learning_analytics.initialized",
            max_records=max_records,
        )

    # -- record / query --

    def add_record(
        self,
        agent_id: str,
        metric: LearningMetric = (LearningMetric.ACCURACY_IMPROVEMENT),
        area: KnowledgeArea = (KnowledgeArea.DETECTION),
        baseline_value: float = 0.0,
        current_value: float = 0.0,
        sample_count: int = 0,
    ) -> LearningRecord:
        improvement = 0.0
        if baseline_value > 0:
            improvement = round(
                (current_value - baseline_value) / baseline_value * 100,
                2,
            )
        if improvement >= 10:
            retention = RetentionRate.HIGH
        elif improvement >= 0:
            retention = RetentionRate.MEDIUM
        elif improvement >= -10:
            retention = RetentionRate.LOW
        else:
            retention = RetentionRate.DECAYED
        record = LearningRecord(
            agent_id=agent_id,
            metric=metric,
            area=area,
            retention=retention,
            baseline_value=baseline_value,
            current_value=current_value,
            improvement_pct=improvement,
            sample_count=sample_count,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_learning_analytics.record_added",
            record_id=record.id,
            agent_id=agent_id,
            improvement=improvement,
        )
        return record

    def process(self, agent_id: str) -> LearningAnalysis:
        items = [r for r in self._records if r.agent_id == agent_id]
        if not items:
            return LearningAnalysis(agent_id=agent_id)
        avg_imp = round(
            sum(r.improvement_pct for r in items) / len(items),
            2,
        )
        area_scores: dict[str, list[float]] = {}
        for r in items:
            area_scores.setdefault(r.area.value, []).append(r.improvement_pct)
        area_avgs = {a: sum(v) / len(v) for a, v in area_scores.items()}
        strongest = (
            max(
                area_avgs,
                key=area_avgs.get,  # type: ignore[arg-type]
            )
            if area_avgs
            else ""
        )
        weakest = (
            min(
                area_avgs,
                key=area_avgs.get,  # type: ignore[arg-type]
            )
            if area_avgs
            else ""
        )
        ret_counts: dict[str, int] = {}
        for r in items:
            key = r.retention.value
            ret_counts[key] = ret_counts.get(key, 0) + 1
        overall_ret = (
            max(
                ret_counts,
                key=ret_counts.get,  # type: ignore[arg-type]
            )
            if ret_counts
            else ""
        )
        return LearningAnalysis(
            agent_id=agent_id,
            total_metrics=len(items),
            avg_improvement=avg_imp,
            strongest_area=strongest,
            weakest_area=weakest,
            overall_retention=overall_ret,
        )

    def generate_report(self) -> LearningReport:
        by_metric: dict[str, int] = {}
        by_area: dict[str, int] = {}
        by_retention: dict[str, int] = {}
        for r in self._records:
            by_metric[r.metric.value] = by_metric.get(r.metric.value, 0) + 1
            by_area[r.area.value] = by_area.get(r.area.value, 0) + 1
            by_retention[r.retention.value] = by_retention.get(r.retention.value, 0) + 1
        total = len(self._records)
        avg_imp = (
            round(
                sum(r.improvement_pct for r in self._records) / total,
                2,
            )
            if total
            else 0.0
        )
        decayed = sum(1 for r in self._records if r.retention == RetentionRate.DECAYED)
        recs: list[str] = []
        if decayed > 0:
            recs.append(f"{decayed} metric(s) show decayed retention")
        if avg_imp < 0:
            recs.append("Negative avg improvement — investigate regression")
        if not recs:
            recs.append("Agent learning progress is healthy")
        return LearningReport(
            total_records=total,
            by_metric=by_metric,
            by_area=by_area,
            by_retention=by_retention,
            avg_improvement_pct=avg_imp,
            decayed_count=decayed,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        area_dist: dict[str, int] = {}
        for r in self._records:
            key = r.area.value
            area_dist[key] = area_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "area_distribution": area_dist,
            "unique_agents": len({r.agent_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("agent_learning_analytics.cleared")
        return {"status": "cleared"}

    # -- domain operations --

    def measure_learning_rate(
        self,
        agent_id: str,
        area: KnowledgeArea | None = None,
        window: int = 20,
    ) -> dict[str, Any]:
        """Measure learning rate for an agent."""
        items = [r for r in self._records if r.agent_id == agent_id]
        if area:
            items = [r for r in items if r.area == area]
        recent = items[-window:]
        if len(recent) < 2:
            return {
                "agent_id": agent_id,
                "sufficient_data": False,
                "count": len(recent),
            }
        improvements = [r.improvement_pct for r in recent]
        half = len(improvements) // 2
        first_avg = sum(improvements[:half]) / max(half, 1)
        second_avg = sum(improvements[half:]) / max(len(improvements) - half, 1)
        rate = round(second_avg - first_avg, 4)
        return {
            "agent_id": agent_id,
            "sufficient_data": True,
            "area": area.value if area else "all",
            "learning_rate": rate,
            "accelerating": rate > 0,
            "recent_avg_improvement": round(second_avg, 2),
        }

    def track_knowledge_decay(
        self,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        """Track knowledge decay across agents."""
        targets = self._records
        if agent_id:
            targets = [r for r in targets if r.agent_id == agent_id]
        decayed = [r for r in targets if r.retention == RetentionRate.DECAYED]
        low = [r for r in targets if r.retention == RetentionRate.LOW]
        total = len(targets)
        decay_rate = round(len(decayed) / total * 100, 2) if total else 0.0
        areas_at_risk: dict[str, int] = {}
        for r in decayed + low:
            key = r.area.value
            areas_at_risk[key] = areas_at_risk.get(key, 0) + 1
        return {
            "agent_id": agent_id or "all",
            "total_metrics": total,
            "decayed_count": len(decayed),
            "low_retention_count": len(low),
            "decay_rate_pct": decay_rate,
            "areas_at_risk": areas_at_risk,
        }

    def benchmark_agent_growth(
        self,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Benchmark growth across all agents."""
        agent_data: dict[str, list[float]] = {}
        for r in self._records:
            agent_data.setdefault(r.agent_id, []).append(r.improvement_pct)
        results: list[dict[str, Any]] = []
        for agent_id, imps in agent_data.items():
            avg = round(sum(imps) / len(imps), 2)
            results.append(
                {
                    "agent_id": agent_id,
                    "avg_improvement_pct": avg,
                    "total_metrics": len(imps),
                    "max_improvement": round(max(imps), 2),
                    "min_improvement": round(min(imps), 2),
                }
            )
        results.sort(
            key=lambda x: x["avg_improvement_pct"],
            reverse=True,
        )
        logger.info(
            "agent_learning_analytics.benchmark_complete",
            agents=len(results),
        )
        return results[:limit]
