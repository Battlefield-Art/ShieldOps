"""AgentEvolutionTrackerEngine — Track agent capability evolution over time."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EvolutionPhase(StrEnum):
    BOOTSTRAP = "bootstrap"
    LEARNING = "learning"
    PROFICIENT = "proficient"
    EXPERT = "expert"
    PLATEAU = "plateau"


class CapabilityDomain(StrEnum):
    INVESTIGATION = "investigation"
    REMEDIATION = "remediation"
    SECURITY = "security"
    OPTIMIZATION = "optimization"


class EvolutionTrend(StrEnum):
    ACCELERATING = "accelerating"
    STEADY = "steady"
    DECELERATING = "decelerating"
    REGRESSING = "regressing"


# --- Models ---


class AgentEvolutionTrackerRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    evolution_phase: EvolutionPhase = EvolutionPhase.BOOTSTRAP
    capability_domain: CapabilityDomain = CapabilityDomain.INVESTIGATION
    evolution_trend: EvolutionTrend = EvolutionTrend.STEADY
    score: float = 0.0
    version: str = ""
    skill_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentEvolutionTrackerAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    evolution_phase: EvolutionPhase = EvolutionPhase.BOOTSTRAP
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentEvolutionTrackerReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_evolution_phase: dict[str, int] = Field(default_factory=dict)
    by_capability_domain: dict[str, int] = Field(default_factory=dict)
    by_evolution_trend: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentEvolutionTrackerEngine:
    """Track agent capability evolution over time."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AgentEvolutionTrackerRecord] = []
        self._analyses: list[AgentEvolutionTrackerAnalysis] = []
        logger.info(
            "agent_evolution_tracker_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        evolution_phase: EvolutionPhase = EvolutionPhase.BOOTSTRAP,
        capability_domain: CapabilityDomain = CapabilityDomain.INVESTIGATION,
        evolution_trend: EvolutionTrend = EvolutionTrend.STEADY,
        score: float = 0.0,
        version: str = "",
        skill_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> AgentEvolutionTrackerRecord:
        record = AgentEvolutionTrackerRecord(
            name=name,
            evolution_phase=evolution_phase,
            capability_domain=capability_domain,
            evolution_trend=evolution_trend,
            score=score,
            version=version,
            skill_count=skill_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_evolution_tracker_engine.record_added",
            record_id=record.id,
            name=name,
            evolution_phase=evolution_phase.value,
            capability_domain=capability_domain.value,
        )
        return record

    def get_record(self, record_id: str) -> AgentEvolutionTrackerRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        evolution_phase: EvolutionPhase | None = None,
        capability_domain: CapabilityDomain | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AgentEvolutionTrackerRecord]:
        results = list(self._records)
        if evolution_phase is not None:
            results = [r for r in results if r.evolution_phase == evolution_phase]
        if capability_domain is not None:
            results = [r for r in results if r.capability_domain == capability_domain]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        evolution_phase: EvolutionPhase = EvolutionPhase.BOOTSTRAP,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AgentEvolutionTrackerAnalysis:
        analysis = AgentEvolutionTrackerAnalysis(
            name=name,
            evolution_phase=evolution_phase,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "agent_evolution_tracker_engine.analysis_added",
            name=name,
            evolution_phase=evolution_phase.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def track_capability_growth(self) -> list[dict[str, Any]]:
        """Track capability growth per agent across domains."""
        agent_data: dict[str, list[AgentEvolutionTrackerRecord]] = {}
        for r in self._records:
            agent_data.setdefault(r.name, []).append(r)
        results: list[dict[str, Any]] = []
        phase_order = list(EvolutionPhase)
        for agent, records in agent_data.items():
            domains = sorted({r.capability_domain.value for r in records})
            phases = {r.evolution_phase for r in records}
            max_phase_idx = max((phase_order.index(p) for p in phases), default=0)
            total_skills = sum(r.skill_count for r in records)
            results.append(
                {
                    "agent": agent,
                    "domains": domains,
                    "current_phase": phase_order[max_phase_idx].value,
                    "phase_depth": max_phase_idx + 1,
                    "total_skills": total_skills,
                    "avg_score": round(sum(r.score for r in records) / len(records), 2),
                    "versions": sorted({r.version for r in records if r.version}),
                }
            )
        return sorted(results, key=lambda x: x["phase_depth"], reverse=True)

    def detect_performance_plateaus(self) -> list[dict[str, Any]]:
        """Detect agents that have plateaued in performance."""
        plateaus: list[dict[str, Any]] = []
        agent_data: dict[str, list[AgentEvolutionTrackerRecord]] = {}
        for r in self._records:
            agent_data.setdefault(r.name, []).append(r)
        for agent, records in agent_data.items():
            plateau_records = [
                r
                for r in records
                if r.evolution_phase == EvolutionPhase.PLATEAU
                or r.evolution_trend == EvolutionTrend.DECELERATING
            ]
            if plateau_records:
                plateaus.append(
                    {
                        "agent": agent,
                        "plateau_count": len(plateau_records),
                        "total_records": len(records),
                        "plateau_pct": round(len(plateau_records) / len(records) * 100, 1),
                        "domains_affected": sorted(
                            {r.capability_domain.value for r in plateau_records}
                        ),
                        "avg_score": round(
                            sum(r.score for r in plateau_records) / len(plateau_records), 2
                        ),
                    }
                )
        return sorted(plateaus, key=lambda x: x["plateau_pct"], reverse=True)

    def recommend_evolution_path(self) -> list[dict[str, Any]]:
        """Recommend evolution paths for agents based on current phase."""
        phase_order = list(EvolutionPhase)
        agent_data: dict[str, list[AgentEvolutionTrackerRecord]] = {}
        for r in self._records:
            agent_data.setdefault(r.name, []).append(r)
        recommendations: list[dict[str, Any]] = []
        for agent, records in agent_data.items():
            phases = {r.evolution_phase for r in records}
            max_idx = max((phase_order.index(p) for p in phases), default=0)
            current_phase = phase_order[max_idx]
            regressing = [r for r in records if r.evolution_trend == EvolutionTrend.REGRESSING]
            if regressing:
                recommendations.append(
                    {
                        "agent": agent,
                        "current_phase": current_phase.value,
                        "issue": "regression_detected",
                        "priority": "high",
                        "suggestion": (
                            f"Agent {agent} is regressing — investigate root cause "
                            f"in domains: {sorted({r.capability_domain.value for r in regressing})}"
                        ),
                    }
                )
            elif current_phase == EvolutionPhase.PLATEAU:
                recommendations.append(
                    {
                        "agent": agent,
                        "current_phase": current_phase.value,
                        "issue": "plateau",
                        "priority": "medium",
                        "suggestion": (
                            f"Agent {agent} has plateaued — consider new training data "
                            f"or capability expansion"
                        ),
                    }
                )
            elif max_idx < len(phase_order) - 2:
                next_phase = phase_order[max_idx + 1]
                recommendations.append(
                    {
                        "agent": agent,
                        "current_phase": current_phase.value,
                        "issue": "growth_opportunity",
                        "priority": "low",
                        "suggestion": (
                            f"Agent {agent} can advance to {next_phase.value} — "
                            f"focus on skill development"
                        ),
                    }
                )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else (1 if x["priority"] == "medium" else 2),
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.evolution_phase.value
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
                        "evolution_phase": r.evolution_phase.value,
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

    def generate_report(self) -> AgentEvolutionTrackerReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.evolution_phase.value] = by_e1.get(r.evolution_phase.value, 0) + 1
            by_e2[r.capability_domain.value] = by_e2.get(r.capability_domain.value, 0) + 1
            by_e3[r.evolution_trend.value] = by_e3.get(r.evolution_trend.value, 0) + 1
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
            recs.append("Agent Evolution Tracker Engine is healthy")
        return AgentEvolutionTrackerReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_evolution_phase=by_e1,
            by_capability_domain=by_e2,
            by_evolution_trend=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_evolution_tracker_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.evolution_phase.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "evolution_phase_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
