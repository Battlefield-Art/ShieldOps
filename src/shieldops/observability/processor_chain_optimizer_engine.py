"""Processor Chain Optimizer Engine —
evaluate chain ordering, measure processor drop impact,
recommend chain simplification."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ProcessorType(StrEnum):
    BATCH = "batch"
    FILTER = "filter"
    TRANSFORM = "transform"
    SAMPLING = "sampling"


class ChainEfficiency(StrEnum):
    OPTIMAL = "optimal"
    SUBOPTIMAL = "suboptimal"
    WASTEFUL = "wasteful"
    BROKEN = "broken"


class OptimizationGoal(StrEnum):
    MINIMIZE_LATENCY = "minimize_latency"
    MAXIMIZE_THROUGHPUT = "maximize_throughput"
    REDUCE_COST = "reduce_cost"
    IMPROVE_FIDELITY = "improve_fidelity"


# --- Models ---


class ProcessorChainRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    chain_id: str = ""
    processor_type: ProcessorType = ProcessorType.BATCH
    chain_efficiency: ChainEfficiency = ChainEfficiency.OPTIMAL
    optimization_goal: OptimizationGoal = OptimizationGoal.MAXIMIZE_THROUGHPUT
    chain_position: int = 0
    drop_rate_pct: float = 0.0
    latency_added_ms: float = 0.0
    throughput_items_per_sec: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ProcessorChainAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    chain_id: str = ""
    chain_efficiency: ChainEfficiency = ChainEfficiency.OPTIMAL
    ordering_score: float = 0.0
    drop_impact_pct: float = 0.0
    simplification_possible: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ProcessorChainReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_drop_rate_pct: float = 0.0
    avg_latency_added_ms: float = 0.0
    by_processor_type: dict[str, int] = Field(default_factory=dict)
    by_chain_efficiency: dict[str, int] = Field(default_factory=dict)
    by_optimization_goal: dict[str, int] = Field(default_factory=dict)
    inefficient_chains: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ProcessorChainOptimizerEngine:
    """Evaluate chain ordering, measure processor drop impact,
    recommend chain simplification."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[ProcessorChainRecord] = []
        self._analyses: dict[str, ProcessorChainAnalysis] = {}
        logger.info("processor_chain_optimizer_engine.init", max_records=max_records)

    def add_record(
        self,
        chain_id: str = "",
        processor_type: ProcessorType = ProcessorType.BATCH,
        chain_efficiency: ChainEfficiency = ChainEfficiency.OPTIMAL,
        optimization_goal: OptimizationGoal = OptimizationGoal.MAXIMIZE_THROUGHPUT,
        chain_position: int = 0,
        drop_rate_pct: float = 0.0,
        latency_added_ms: float = 0.0,
        throughput_items_per_sec: float = 0.0,
        description: str = "",
    ) -> ProcessorChainRecord:
        record = ProcessorChainRecord(
            chain_id=chain_id,
            processor_type=processor_type,
            chain_efficiency=chain_efficiency,
            optimization_goal=optimization_goal,
            chain_position=chain_position,
            drop_rate_pct=drop_rate_pct,
            latency_added_ms=latency_added_ms,
            throughput_items_per_sec=throughput_items_per_sec,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "processor_chain.record_added",
            record_id=record.id,
            chain_id=chain_id,
        )
        return record

    def process(self, key: str) -> ProcessorChainAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        efficiency_weights = {
            ChainEfficiency.OPTIMAL: 1.0,
            ChainEfficiency.SUBOPTIMAL: 0.7,
            ChainEfficiency.WASTEFUL: 0.4,
            ChainEfficiency.BROKEN: 0.0,
        }
        ordering_score = round(
            efficiency_weights.get(rec.chain_efficiency, 0.5) * 100.0,
            2,
        )
        drop_impact = round(rec.drop_rate_pct * (rec.chain_position + 1) / 10.0, 2)
        simplification_possible = (
            rec.chain_efficiency in (ChainEfficiency.WASTEFUL, ChainEfficiency.SUBOPTIMAL)
            or rec.drop_rate_pct > 20.0
        )
        analysis = ProcessorChainAnalysis(
            chain_id=rec.chain_id,
            chain_efficiency=rec.chain_efficiency,
            ordering_score=ordering_score,
            drop_impact_pct=drop_impact,
            simplification_possible=simplification_possible,
            description=(f"Chain {rec.chain_id} ordering score {ordering_score:.1f}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ProcessorChainReport:
        by_type: dict[str, int] = {}
        by_eff: dict[str, int] = {}
        by_goal: dict[str, int] = {}
        drop_vals: list[float] = []
        lat_vals: list[float] = []
        inefficient: list[str] = []
        for r in self._records:
            kt = r.processor_type.value
            by_type[kt] = by_type.get(kt, 0) + 1
            ke = r.chain_efficiency.value
            by_eff[ke] = by_eff.get(ke, 0) + 1
            kg = r.optimization_goal.value
            by_goal[kg] = by_goal.get(kg, 0) + 1
            drop_vals.append(r.drop_rate_pct)
            lat_vals.append(r.latency_added_ms)
            if (
                r.chain_efficiency in (ChainEfficiency.WASTEFUL, ChainEfficiency.BROKEN)
                and r.chain_id not in inefficient
            ):
                inefficient.append(r.chain_id)
        avg_drop = round(sum(drop_vals) / len(drop_vals), 2) if drop_vals else 0.0
        avg_lat = round(sum(lat_vals) / len(lat_vals), 2) if lat_vals else 0.0
        recs: list[str] = []
        if inefficient:
            recs.append(f"{len(inefficient)} chains marked wasteful or broken")
        if avg_drop > 10.0:
            recs.append(f"Average drop rate {avg_drop:.1f}% — review filter placement")
        if not recs:
            recs.append("Processor chains are well-ordered and efficient")
        return ProcessorChainReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_drop_rate_pct=avg_drop,
            avg_latency_added_ms=avg_lat,
            by_processor_type=by_type,
            by_chain_efficiency=by_eff,
            by_optimization_goal=by_goal,
            inefficient_chains=inefficient[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        eff_dist: dict[str, int] = {}
        for r in self._records:
            k = r.chain_efficiency.value
            eff_dist[k] = eff_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "efficiency_distribution": eff_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("processor_chain_optimizer_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def evaluate_chain_ordering(self) -> list[dict[str, Any]]:
        """Evaluate whether filter processors precede transform processors."""
        chain_data: dict[str, list[ProcessorChainRecord]] = {}
        for r in self._records:
            chain_data.setdefault(r.chain_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, recs in chain_data.items():
            sorted_recs = sorted(recs, key=lambda x: x.chain_position)
            positions = [(r.processor_type.value, r.chain_position) for r in sorted_recs]
            filter_positions = [p for p_type, p in positions if p_type == "filter"]
            transform_positions = [p for p_type, p in positions if p_type == "transform"]
            ordering_ok = True
            if filter_positions and transform_positions:
                ordering_ok = min(filter_positions) < min(transform_positions)
            results.append(
                {
                    "chain_id": cid,
                    "ordering_ok": ordering_ok,
                    "processor_sequence": [pt for pt, _ in positions],
                    "processor_count": len(recs),
                }
            )
        results.sort(key=lambda x: x["ordering_ok"])
        return results

    def measure_processor_drop_impact(self) -> list[dict[str, Any]]:
        """Measure total drop impact per chain."""
        chain_data: dict[str, list[ProcessorChainRecord]] = {}
        for r in self._records:
            chain_data.setdefault(r.chain_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, recs in chain_data.items():
            total_drop = sum(r.drop_rate_pct for r in recs)
            max_drop = max(r.drop_rate_pct for r in recs)
            culprit_type = max(recs, key=lambda x: x.drop_rate_pct).processor_type.value
            results.append(
                {
                    "chain_id": cid,
                    "total_drop_pct": round(total_drop, 2),
                    "max_single_drop_pct": round(max_drop, 2),
                    "highest_drop_processor_type": culprit_type,
                    "processor_count": len(recs),
                }
            )
        results.sort(key=lambda x: x["total_drop_pct"], reverse=True)
        return results

    def recommend_chain_simplification(self) -> list[dict[str, Any]]:
        """Recommend which chains can be simplified."""
        chain_data: dict[str, list[ProcessorChainRecord]] = {}
        for r in self._records:
            chain_data.setdefault(r.chain_id, []).append(r)
        results: list[dict[str, Any]] = []
        for cid, recs in chain_data.items():
            wasteful = sum(1 for r in recs if r.chain_efficiency == ChainEfficiency.WASTEFUL)
            redundant_types: dict[str, int] = {}
            for r in recs:
                redundant_types[r.processor_type.value] = (
                    redundant_types.get(r.processor_type.value, 0) + 1
                )
            has_redundancy = any(c > 1 for c in redundant_types.values())
            simplification_gain = wasteful + (1 if has_redundancy else 0)
            if simplification_gain > 0:
                results.append(
                    {
                        "chain_id": cid,
                        "wasteful_processors": wasteful,
                        "has_redundant_types": has_redundancy,
                        "simplification_gain": simplification_gain,
                        "current_length": len(recs),
                        "recommended_length": max(1, len(recs) - simplification_gain),
                    }
                )
        results.sort(key=lambda x: x["simplification_gain"], reverse=True)
        return results
