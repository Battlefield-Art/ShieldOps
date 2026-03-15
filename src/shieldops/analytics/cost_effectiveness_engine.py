"""CostEffectivenessEngine — Measure agent cost-effectiveness."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CostCategory(StrEnum):
    LLM_TOKENS = "llm_tokens"
    COMPUTE = "compute"
    API_CALLS = "api_calls"
    HUMAN_TIME = "human_time"


class ROIIndicator(StrEnum):
    POSITIVE = "positive"
    NEUTRAL = "neutral"
    NEGATIVE = "negative"


class EfficiencyQuartile(StrEnum):
    TOP = "top"
    UPPER = "upper"
    LOWER = "lower"
    BOTTOM = "bottom"


# --- Models ---


class CostEffectivenessRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    cost_category: CostCategory = CostCategory.LLM_TOKENS
    roi_indicator: ROIIndicator = ROIIndicator.NEUTRAL
    efficiency_quartile: EfficiencyQuartile = EfficiencyQuartile.UPPER
    score: float = 0.0
    cost_usd: float = 0.0
    time_saved_min: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CostEffectivenessAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    cost_category: CostCategory = CostCategory.LLM_TOKENS
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CostEffectivenessReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_cost_category: dict[str, int] = Field(default_factory=dict)
    by_roi_indicator: dict[str, int] = Field(default_factory=dict)
    by_efficiency_quartile: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CostEffectivenessEngine:
    """Measure agent cost-effectiveness (cost per investigation, ROI)."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[CostEffectivenessRecord] = []
        self._analyses: list[CostEffectivenessAnalysis] = []
        logger.info(
            "cost_effectiveness_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        cost_category: CostCategory = CostCategory.LLM_TOKENS,
        roi_indicator: ROIIndicator = ROIIndicator.NEUTRAL,
        efficiency_quartile: EfficiencyQuartile = EfficiencyQuartile.UPPER,
        score: float = 0.0,
        cost_usd: float = 0.0,
        time_saved_min: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> CostEffectivenessRecord:
        record = CostEffectivenessRecord(
            name=name,
            cost_category=cost_category,
            roi_indicator=roi_indicator,
            efficiency_quartile=efficiency_quartile,
            score=score,
            cost_usd=cost_usd,
            time_saved_min=time_saved_min,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "cost_effectiveness_engine.record_added",
            record_id=record.id,
            name=name,
            cost_category=cost_category.value,
            roi_indicator=roi_indicator.value,
        )
        return record

    def get_record(self, record_id: str) -> CostEffectivenessRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        cost_category: CostCategory | None = None,
        roi_indicator: ROIIndicator | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CostEffectivenessRecord]:
        results = list(self._records)
        if cost_category is not None:
            results = [r for r in results if r.cost_category == cost_category]
        if roi_indicator is not None:
            results = [r for r in results if r.roi_indicator == roi_indicator]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        cost_category: CostCategory = CostCategory.LLM_TOKENS,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CostEffectivenessAnalysis:
        analysis = CostEffectivenessAnalysis(
            name=name,
            cost_category=cost_category,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "cost_effectiveness_engine.analysis_added",
            name=name,
            cost_category=cost_category.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_cost_per_resolution(self) -> list[dict[str, Any]]:
        """Compute cost per resolution by service and category."""
        svc_costs: dict[str, list[CostEffectivenessRecord]] = {}
        for r in self._records:
            svc_costs.setdefault(r.service, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, records in svc_costs.items():
            total_cost = sum(r.cost_usd for r in records)
            total_time_saved = sum(r.time_saved_min for r in records)
            avg_cost = round(total_cost / len(records), 2)
            cost_per_min_saved = (
                round(total_cost / total_time_saved, 4) if total_time_saved > 0 else 0.0
            )
            results.append(
                {
                    "service": svc,
                    "resolution_count": len(records),
                    "total_cost_usd": round(total_cost, 2),
                    "avg_cost_per_resolution": avg_cost,
                    "total_time_saved_min": round(total_time_saved, 1),
                    "cost_per_min_saved": cost_per_min_saved,
                }
            )
        return sorted(results, key=lambda x: x["avg_cost_per_resolution"])

    def compare_agent_vs_manual_cost(self) -> list[dict[str, Any]]:
        """Compare agent cost vs estimated manual cost (using time_saved as proxy)."""
        hourly_rate = 75.0  # assumed engineer hourly rate
        svc_data: dict[str, list[CostEffectivenessRecord]] = {}
        for r in self._records:
            svc_data.setdefault(r.service, []).append(r)
        results: list[dict[str, Any]] = []
        for svc, records in svc_data.items():
            agent_cost = sum(r.cost_usd for r in records)
            manual_cost = sum(r.time_saved_min for r in records) / 60.0 * hourly_rate
            savings = round(manual_cost - agent_cost, 2)
            roi_pct = round(savings / agent_cost * 100, 1) if agent_cost > 0 else 0.0
            results.append(
                {
                    "service": svc,
                    "agent_cost_usd": round(agent_cost, 2),
                    "estimated_manual_cost_usd": round(manual_cost, 2),
                    "savings_usd": savings,
                    "roi_pct": roi_pct,
                    "verdict": "cost_effective" if savings > 0 else "not_cost_effective",
                }
            )
        return sorted(results, key=lambda x: x["savings_usd"], reverse=True)

    def identify_cost_optimization_opportunities(self) -> list[dict[str, Any]]:
        """Identify opportunities to reduce agent costs."""
        recommendations: list[dict[str, Any]] = []
        negative_roi = [r for r in self._records if r.roi_indicator == ROIIndicator.NEGATIVE]
        for r in negative_roi:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "cost_category": r.cost_category.value,
                    "cost_usd": r.cost_usd,
                    "issue": "negative_roi",
                    "priority": "high",
                    "suggestion": f"Optimize {r.cost_category.value} costs for {r.service} "
                    f"(${r.cost_usd})",
                }
            )
        bottom_quartile = [
            r for r in self._records if r.efficiency_quartile == EfficiencyQuartile.BOTTOM
        ]
        for r in bottom_quartile:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "cost_category": r.cost_category.value,
                    "cost_usd": r.cost_usd,
                    "issue": "bottom_quartile_efficiency",
                    "priority": "medium",
                    "suggestion": f"Improve efficiency for {r.name} (bottom quartile)",
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
            key = r.cost_category.value
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
                        "cost_category": r.cost_category.value,
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

    def generate_report(self) -> CostEffectivenessReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.cost_category.value] = by_e1.get(r.cost_category.value, 0) + 1
            by_e2[r.roi_indicator.value] = by_e2.get(r.roi_indicator.value, 0) + 1
            by_e3[r.efficiency_quartile.value] = by_e3.get(r.efficiency_quartile.value, 0) + 1
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
            recs.append("Cost Effectiveness Engine is healthy")
        return CostEffectivenessReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_cost_category=by_e1,
            by_roi_indicator=by_e2,
            by_efficiency_quartile=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("cost_effectiveness_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.cost_category.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "cost_category_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
