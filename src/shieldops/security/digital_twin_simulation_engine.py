"""DigitalTwinSimulationEngine — Manages digital twin security simulations."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SimulationType(StrEnum):
    ATTACK_PATH = "attack_path"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFIL = "data_exfil"
    RANSOMWARE_SPREAD = "ransomware_spread"


class TwinFidelity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SCHEMATIC = "schematic"


class SimulationOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    INCONCLUSIVE = "inconclusive"


# --- Models ---


class SimulationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    twin_id: str = ""
    scenario: str = ""
    simulation_type: SimulationType = SimulationType.ATTACK_PATH
    twin_fidelity: TwinFidelity = TwinFidelity.MEDIUM
    simulation_outcome: SimulationOutcome = SimulationOutcome.INCONCLUSIVE
    score: float = 0.0
    duration_seconds: float = 0.0
    nodes_affected: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class SimulationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    simulation_type: SimulationType = SimulationType.ATTACK_PATH
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class SimulationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_simulation_type: dict[str, int] = Field(default_factory=dict)
    by_twin_fidelity: dict[str, int] = Field(default_factory=dict)
    by_simulation_outcome: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class DigitalTwinSimulationEngine:
    """Manages digital twin security simulations."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[SimulationRecord] = []
        self._analyses: list[SimulationAnalysis] = []
        logger.info(
            "digital_twin_simulation_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        twin_id: str,
        scenario: str = "",
        simulation_type: SimulationType = SimulationType.ATTACK_PATH,
        twin_fidelity: TwinFidelity = TwinFidelity.MEDIUM,
        simulation_outcome: SimulationOutcome = SimulationOutcome.INCONCLUSIVE,
        score: float = 0.0,
        duration_seconds: float = 0.0,
        nodes_affected: int = 0,
        service: str = "",
        team: str = "",
    ) -> SimulationRecord:
        record = SimulationRecord(
            twin_id=twin_id,
            scenario=scenario,
            simulation_type=simulation_type,
            twin_fidelity=twin_fidelity,
            simulation_outcome=simulation_outcome,
            score=score,
            duration_seconds=duration_seconds,
            nodes_affected=nodes_affected,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "digital_twin_simulation_engine.record_added",
            record_id=record.id,
            twin_id=twin_id,
            simulation_type=simulation_type.value,
            simulation_outcome=simulation_outcome.value,
        )
        return record

    def get_record(self, record_id: str) -> SimulationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        simulation_type: SimulationType | None = None,
        twin_fidelity: TwinFidelity | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[SimulationRecord]:
        results = list(self._records)
        if simulation_type is not None:
            results = [r for r in results if r.simulation_type == simulation_type]
        if twin_fidelity is not None:
            results = [r for r in results if r.twin_fidelity == twin_fidelity]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        simulation_type: SimulationType = SimulationType.ATTACK_PATH,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> SimulationAnalysis:
        analysis = SimulationAnalysis(
            name=name,
            simulation_type=simulation_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "digital_twin_simulation_engine.analysis_added",
            name=name,
            simulation_type=simulation_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def run_attack_path_analysis(self) -> list[dict[str, Any]]:
        """Analyze attack paths across digital twin simulations."""
        twin_data: dict[str, list[SimulationRecord]] = {}
        for r in self._records:
            twin_data.setdefault(r.twin_id, []).append(r)
        results: list[dict[str, Any]] = []
        for twin_id, records in twin_data.items():
            attack_sims = [r for r in records if r.simulation_type == SimulationType.ATTACK_PATH]
            if not attack_sims:
                continue
            failed = sum(1 for r in attack_sims if r.simulation_outcome == SimulationOutcome.FAILED)
            passed = sum(1 for r in attack_sims if r.simulation_outcome == SimulationOutcome.PASSED)
            total_nodes = sum(r.nodes_affected for r in attack_sims)
            scores = [r.score for r in attack_sims]
            avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
            results.append(
                {
                    "twin_id": twin_id,
                    "total_attack_simulations": len(attack_sims),
                    "passed": passed,
                    "failed": failed,
                    "total_nodes_affected": total_nodes,
                    "avg_score": avg_score,
                    "attack_success_rate_pct": round(failed / len(attack_sims) * 100, 2)
                    if attack_sims
                    else 0.0,
                    "risk_level": "critical"
                    if failed > passed
                    else ("high" if failed > 0 else "low"),
                }
            )
        return sorted(results, key=lambda x: x["attack_success_rate_pct"], reverse=True)

    def simulate_blast_radius(self) -> list[dict[str, Any]]:
        """Simulate blast radius for each twin based on recorded simulations."""
        twin_data: dict[str, list[SimulationRecord]] = {}
        for r in self._records:
            twin_data.setdefault(r.twin_id, []).append(r)
        results: list[dict[str, Any]] = []
        for twin_id, records in twin_data.items():
            total_nodes = sum(r.nodes_affected for r in records)
            max_nodes = max((r.nodes_affected for r in records), default=0)
            sim_types_hit = {r.simulation_type.value for r in records}
            failed_sims = [r for r in records if r.simulation_outcome == SimulationOutcome.FAILED]
            blast_score = round((max_nodes * len(sim_types_hit)) / max(len(records), 1), 2)
            results.append(
                {
                    "twin_id": twin_id,
                    "total_simulations": len(records),
                    "max_nodes_affected": max_nodes,
                    "total_nodes_affected": total_nodes,
                    "simulation_types_tested": sorted(sim_types_hit),
                    "failed_simulations": len(failed_sims),
                    "blast_radius_score": blast_score,
                    "containment_status": "contained"
                    if blast_score < 10
                    else ("spreading" if blast_score < 50 else "uncontained"),
                }
            )
        return sorted(results, key=lambda x: x["blast_radius_score"], reverse=True)

    def validate_security_controls(self) -> list[dict[str, Any]]:
        """Validate security controls effectiveness via simulation outcomes."""
        service_data: dict[str, list[SimulationRecord]] = {}
        for r in self._records:
            if r.service:
                service_data.setdefault(r.service, []).append(r)
        results: list[dict[str, Any]] = []
        for service, records in service_data.items():
            passed = sum(1 for r in records if r.simulation_outcome == SimulationOutcome.PASSED)
            failed = sum(1 for r in records if r.simulation_outcome == SimulationOutcome.FAILED)
            total = len(records)
            effectiveness = round(passed / total * 100, 2) if total else 0.0
            scores = [r.score for r in records]
            avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
            results.append(
                {
                    "service": service,
                    "total_simulations": total,
                    "controls_passed": passed,
                    "controls_failed": failed,
                    "effectiveness_pct": effectiveness,
                    "avg_score": avg_score,
                    "validation_status": "effective"
                    if effectiveness >= 80
                    else ("degraded" if effectiveness >= 50 else "ineffective"),
                }
            )
        return sorted(results, key=lambda x: x["effectiveness_pct"])

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.simulation_type.value
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
                        "twin_id": r.twin_id,
                        "scenario": r.scenario,
                        "simulation_type": r.simulation_type.value,
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

    def process(self, twin_id: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.twin_id == twin_id]
        if not matched:
            return {"key": twin_id, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": twin_id,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> SimulationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.simulation_type.value] = by_e1.get(r.simulation_type.value, 0) + 1
            by_e2[r.twin_fidelity.value] = by_e2.get(r.twin_fidelity.value, 0) + 1
            by_e3[r.simulation_outcome.value] = by_e3.get(r.simulation_outcome.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["twin_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Digital Twin Simulation Engine is healthy")
        return SimulationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_simulation_type=by_e1,
            by_twin_fidelity=by_e2,
            by_simulation_outcome=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("digital_twin_simulation_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.simulation_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "simulation_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
