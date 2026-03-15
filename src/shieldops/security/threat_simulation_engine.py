"""ThreatSimulationEngine — Track and analyze threat simulation exercises."""

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
    TABLETOP = "tabletop"
    RED_TEAM = "red_team"
    PURPLE_TEAM = "purple_team"
    BREACH_SIMULATION = "breach_simulation"


class SimulationOutcome(StrEnum):
    DETECTED = "detected"
    PARTIALLY_DETECTED = "partially_detected"
    MISSED = "missed"
    BLOCKED = "blocked"


class MitreTactic(StrEnum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"


# --- Models ---


class ThreatSimulationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    simulation_type: SimulationType = SimulationType.TABLETOP
    simulation_outcome: SimulationOutcome = SimulationOutcome.DETECTED
    mitre_tactic: MitreTactic = MitreTactic.INITIAL_ACCESS
    score: float = 0.0
    technique_count: int = 0
    detection_time_seconds: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ThreatSimulationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    simulation_type: SimulationType = SimulationType.TABLETOP
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ThreatSimulationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_simulation_type: dict[str, int] = Field(default_factory=dict)
    by_simulation_outcome: dict[str, int] = Field(default_factory=dict)
    by_mitre_tactic: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ThreatSimulationEngine:
    """Track and analyze threat simulation (purple team) exercises."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ThreatSimulationRecord] = []
        self._analyses: list[ThreatSimulationAnalysis] = []
        logger.info(
            "threat_simulation_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        simulation_type: SimulationType = SimulationType.TABLETOP,
        simulation_outcome: SimulationOutcome = SimulationOutcome.DETECTED,
        mitre_tactic: MitreTactic = MitreTactic.INITIAL_ACCESS,
        score: float = 0.0,
        technique_count: int = 0,
        detection_time_seconds: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ThreatSimulationRecord:
        record = ThreatSimulationRecord(
            name=name,
            simulation_type=simulation_type,
            simulation_outcome=simulation_outcome,
            mitre_tactic=mitre_tactic,
            score=score,
            technique_count=technique_count,
            detection_time_seconds=detection_time_seconds,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "threat_simulation_engine.record_added",
            record_id=record.id,
            name=name,
            simulation_type=simulation_type.value,
            simulation_outcome=simulation_outcome.value,
        )
        return record

    def get_record(self, record_id: str) -> ThreatSimulationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        simulation_type: SimulationType | None = None,
        simulation_outcome: SimulationOutcome | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ThreatSimulationRecord]:
        results = list(self._records)
        if simulation_type is not None:
            results = [r for r in results if r.simulation_type == simulation_type]
        if simulation_outcome is not None:
            results = [r for r in results if r.simulation_outcome == simulation_outcome]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        simulation_type: SimulationType = SimulationType.TABLETOP,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ThreatSimulationAnalysis:
        analysis = ThreatSimulationAnalysis(
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
            "threat_simulation_engine.analysis_added",
            name=name,
            simulation_type=simulation_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_detection_gaps(self) -> list[dict[str, Any]]:
        """Identify MITRE tactics where detections are weak or missing."""
        tactic_outcomes: dict[str, dict[str, int]] = {}
        for r in self._records:
            t = r.mitre_tactic.value
            tactic_outcomes.setdefault(t, {})
            o = r.simulation_outcome.value
            tactic_outcomes[t][o] = tactic_outcomes[t].get(o, 0) + 1
        gaps: list[dict[str, Any]] = []
        for tactic, outcomes in tactic_outcomes.items():
            total = sum(outcomes.values())
            missed = outcomes.get("missed", 0)
            partial = outcomes.get("partially_detected", 0)
            gap_pct = round((missed + partial) / total * 100, 1) if total else 0.0
            if missed > 0 or partial > 0:
                gaps.append(
                    {
                        "tactic": tactic,
                        "total_simulations": total,
                        "missed": missed,
                        "partially_detected": partial,
                        "gap_pct": gap_pct,
                        "severity": "critical" if missed > partial else "warning",
                    }
                )
        return sorted(gaps, key=lambda x: x["gap_pct"], reverse=True)

    def compute_detection_coverage(self) -> list[dict[str, Any]]:
        """Compute detection coverage per simulation type."""
        type_data: dict[str, list[ThreatSimulationRecord]] = {}
        for r in self._records:
            type_data.setdefault(r.simulation_type.value, []).append(r)
        results: list[dict[str, Any]] = []
        for sim_type, records in type_data.items():
            total = len(records)
            detected = sum(
                1
                for r in records
                if r.simulation_outcome in (SimulationOutcome.DETECTED, SimulationOutcome.BLOCKED)
            )
            coverage = round(detected / total * 100, 1) if total else 0.0
            avg_time = (
                round(sum(r.detection_time_seconds for r in records) / total, 2) if total else 0.0
            )
            results.append(
                {
                    "simulation_type": sim_type,
                    "total_simulations": total,
                    "detected": detected,
                    "coverage_pct": coverage,
                    "avg_detection_time_seconds": avg_time,
                }
            )
        return sorted(results, key=lambda x: x["coverage_pct"])

    def recommend_detection_improvements(self) -> list[dict[str, Any]]:
        """Recommend detection improvements based on simulation outcomes."""
        recommendations: list[dict[str, Any]] = []
        missed = [r for r in self._records if r.simulation_outcome == SimulationOutcome.MISSED]
        for r in missed:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "tactic": r.mitre_tactic.value,
                    "issue": "missed_detection",
                    "priority": "critical",
                    "suggestion": (
                        f"Create detection for {r.mitre_tactic.value} ({r.simulation_type.value})"
                    ),
                }
            )
        partial = [
            r for r in self._records if r.simulation_outcome == SimulationOutcome.PARTIALLY_DETECTED
        ]
        for r in partial:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "tactic": r.mitre_tactic.value,
                    "issue": "partial_detection",
                    "priority": "high",
                    "suggestion": (f"Improve detection for {r.mitre_tactic.value}"),
                }
            )
        low_score = [
            r
            for r in self._records
            if r.score < self._threshold
            and r.simulation_outcome in (SimulationOutcome.DETECTED, SimulationOutcome.BLOCKED)
        ]
        for r in low_score:
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "tactic": r.mitre_tactic.value,
                    "issue": "low_score",
                    "priority": "medium",
                    "suggestion": f"Tune detection quality (score: {r.score})",
                }
            )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(recommendations, key=lambda x: priority_order.get(x["priority"], 3))

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
                        "name": r.name,
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

    def generate_report(self) -> ThreatSimulationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.simulation_type.value] = by_e1.get(r.simulation_type.value, 0) + 1
            by_e2[r.simulation_outcome.value] = by_e2.get(r.simulation_outcome.value, 0) + 1
            by_e3[r.mitre_tactic.value] = by_e3.get(r.mitre_tactic.value, 0) + 1
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
            recs.append("Threat Simulation Engine is healthy")
        return ThreatSimulationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_simulation_type=by_e1,
            by_simulation_outcome=by_e2,
            by_mitre_tactic=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("threat_simulation_engine.cleared")
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
