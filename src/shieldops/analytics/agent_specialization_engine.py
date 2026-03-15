"""AgentSpecializationEngine — Track and optimize agent specialization."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SpecializationDomain(StrEnum):
    INFRASTRUCTURE = "infrastructure"
    SECURITY = "security"
    COST = "cost"
    COMPLIANCE = "compliance"
    OBSERVABILITY = "observability"


class ProficiencyLevel(StrEnum):
    NOVICE = "novice"
    COMPETENT = "competent"
    PROFICIENT = "proficient"
    EXPERT = "expert"


class AdaptationSpeed(StrEnum):
    FAST = "fast"
    MODERATE = "moderate"
    SLOW = "slow"


# --- Models ---


class AgentSpecializationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    domain: SpecializationDomain = SpecializationDomain.INFRASTRUCTURE
    proficiency: ProficiencyLevel = ProficiencyLevel.COMPETENT
    adaptation: AdaptationSpeed = AdaptationSpeed.MODERATE
    score: float = 0.0
    task_count: int = 0
    success_rate: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentSpecializationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    domain: SpecializationDomain = SpecializationDomain.INFRASTRUCTURE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AgentSpecializationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_domain: dict[str, int] = Field(default_factory=dict)
    by_proficiency: dict[str, int] = Field(default_factory=dict)
    by_adaptation: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentSpecializationEngine:
    """Track and optimize agent specialization across task domains."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AgentSpecializationRecord] = []
        self._analyses: list[AgentSpecializationAnalysis] = []
        logger.info(
            "agent_specialization_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        domain: SpecializationDomain = SpecializationDomain.INFRASTRUCTURE,
        proficiency: ProficiencyLevel = ProficiencyLevel.COMPETENT,
        adaptation: AdaptationSpeed = AdaptationSpeed.MODERATE,
        score: float = 0.0,
        task_count: int = 0,
        success_rate: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> AgentSpecializationRecord:
        record = AgentSpecializationRecord(
            name=name,
            domain=domain,
            proficiency=proficiency,
            adaptation=adaptation,
            score=score,
            task_count=task_count,
            success_rate=success_rate,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_specialization_engine.record_added",
            record_id=record.id,
            name=name,
            domain=domain.value,
            proficiency=proficiency.value,
        )
        return record

    def get_record(self, record_id: str) -> AgentSpecializationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        domain: SpecializationDomain | None = None,
        proficiency: ProficiencyLevel | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AgentSpecializationRecord]:
        results = list(self._records)
        if domain is not None:
            results = [r for r in results if r.domain == domain]
        if proficiency is not None:
            results = [r for r in results if r.proficiency == proficiency]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        domain: SpecializationDomain = SpecializationDomain.INFRASTRUCTURE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AgentSpecializationAnalysis:
        analysis = AgentSpecializationAnalysis(
            name=name,
            domain=domain,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "agent_specialization_engine.analysis_added",
            name=name,
            domain=domain.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_agent_specializations(self) -> list[dict[str, Any]]:
        """Identify which agents are specialized in which domains."""
        agent_data: dict[str, dict[str, list[float]]] = {}
        for r in self._records:
            agent_data.setdefault(r.name, {})
            agent_data[r.name].setdefault(r.domain.value, []).append(r.success_rate)
        results: list[dict[str, Any]] = []
        for agent, domains in agent_data.items():
            domain_avgs: dict[str, float] = {}
            best_domain = ""
            best_avg = 0.0
            for dom, rates in domains.items():
                avg = round(sum(rates) / len(rates), 2)
                domain_avgs[dom] = avg
                if avg > best_avg:
                    best_avg = avg
                    best_domain = dom
            results.append(
                {
                    "agent": agent,
                    "best_domain": best_domain,
                    "best_success_rate": best_avg,
                    "domain_scores": domain_avgs,
                    "domains_covered": len(domains),
                }
            )
        return sorted(results, key=lambda x: x["best_success_rate"], reverse=True)

    def detect_skill_overlap(self) -> list[dict[str, Any]]:
        """Detect domains where multiple agents overlap in skill."""
        domain_agents: dict[str, list[str]] = {}
        for r in self._records:
            if r.proficiency in (ProficiencyLevel.PROFICIENT, ProficiencyLevel.EXPERT):
                domain_agents.setdefault(r.domain.value, [])
                if r.name not in domain_agents[r.domain.value]:
                    domain_agents[r.domain.value].append(r.name)
        overlaps: list[dict[str, Any]] = []
        for dom, agents in domain_agents.items():
            if len(agents) > 1:
                overlaps.append(
                    {
                        "domain": dom,
                        "agent_count": len(agents),
                        "agents": agents,
                        "redundancy": "high"
                        if len(agents) > 3
                        else "medium"
                        if len(agents) > 1
                        else "low",
                    }
                )
        return sorted(overlaps, key=lambda x: x["agent_count"], reverse=True)

    def recommend_agent_assignments(self) -> list[dict[str, Any]]:
        """Recommend optimal agent-to-domain assignments."""
        recommendations: list[dict[str, Any]] = []
        # Find domains with no expert/proficient agents
        domain_coverage: dict[str, bool] = {d.value: False for d in SpecializationDomain}
        for r in self._records:
            if r.proficiency in (ProficiencyLevel.PROFICIENT, ProficiencyLevel.EXPERT):
                domain_coverage[r.domain.value] = True
        for dom, covered in domain_coverage.items():
            if not covered:
                # Find best candidate
                candidates = [r for r in self._records if r.domain.value == dom]
                if candidates:
                    best = max(candidates, key=lambda x: x.success_rate)
                    recommendations.append(
                        {
                            "domain": dom,
                            "issue": "no_expert_coverage",
                            "best_candidate": best.name,
                            "current_proficiency": best.proficiency.value,
                            "success_rate": best.success_rate,
                            "priority": "high",
                            "suggestion": f"Upskill {best.name} for {dom} domain",
                        }
                    )
                else:
                    recommendations.append(
                        {
                            "domain": dom,
                            "issue": "no_coverage",
                            "best_candidate": "",
                            "current_proficiency": "",
                            "success_rate": 0.0,
                            "priority": "critical",
                            "suggestion": f"Assign agent to uncovered {dom} domain",
                        }
                    )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "critical" else 1 if x["priority"] == "high" else 2,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.domain.value
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
                        "domain": r.domain.value,
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

    def generate_report(self) -> AgentSpecializationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.domain.value] = by_e1.get(r.domain.value, 0) + 1
            by_e2[r.proficiency.value] = by_e2.get(r.proficiency.value, 0) + 1
            by_e3[r.adaptation.value] = by_e3.get(r.adaptation.value, 0) + 1
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
            recs.append("Agent Specialization Engine is healthy")
        return AgentSpecializationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_domain=by_e1,
            by_proficiency=by_e2,
            by_adaptation=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_specialization_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.domain.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "domain_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
