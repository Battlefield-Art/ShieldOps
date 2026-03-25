"""Adversarial Scenario Generator Engine — track generated adversarial test scenarios."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ScenarioType(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class TargetSurface(StrEnum):
    LLM_API = "llm_api"
    MCP_SERVER = "mcp_server"
    SERVICE_ACCOUNT = "service_account"
    CLOUD_IAM = "cloud_iam"
    KUBERNETES_RBAC = "kubernetes_rbac"


class ScenarioComplexity(StrEnum):
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    APT_LEVEL = "apt_level"
    NOVEL = "novel"


# --- Models ---


class ScenarioRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario_name: str = ""
    scenario_type: ScenarioType = ScenarioType.PROMPT_INJECTION
    target_surface: TargetSurface = TargetSurface.LLM_API
    scenario_complexity: ScenarioComplexity = ScenarioComplexity.BASIC
    mitre_techniques: str = ""
    success_probability: float = 0.0
    defense_coverage: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ScenarioAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario_name: str = ""
    scenario_type: ScenarioType = ScenarioType.PROMPT_INJECTION
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ScenarioReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    high_risk_count: int = 0
    avg_success_probability: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_surface: dict[str, int] = Field(default_factory=dict)
    by_complexity: dict[str, int] = Field(default_factory=dict)
    top_undefended: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AdversarialScenarioGeneratorEngine:
    """Track and analyze generated adversarial test scenarios."""

    def __init__(
        self,
        max_records: int = 200000,
        coverage_threshold: float = 75.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = coverage_threshold
        self._records: list[ScenarioRecord] = []
        self._analyses: list[ScenarioAnalysis] = []
        logger.info(
            "adversarial_scenario_generator_engine.initialized",
            max_records=max_records,
            coverage_threshold=coverage_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        scenario_name: str,
        scenario_type: ScenarioType = ScenarioType.PROMPT_INJECTION,
        target_surface: TargetSurface = TargetSurface.LLM_API,
        scenario_complexity: ScenarioComplexity = ScenarioComplexity.BASIC,
        mitre_techniques: str = "",
        success_probability: float = 0.0,
        defense_coverage: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ScenarioRecord:
        record = ScenarioRecord(
            scenario_name=scenario_name,
            scenario_type=scenario_type,
            target_surface=target_surface,
            scenario_complexity=scenario_complexity,
            mitre_techniques=mitre_techniques,
            success_probability=success_probability,
            defense_coverage=defense_coverage,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "adversarial_scenario_generator_engine.record_added",
            record_id=record.id,
            scenario_name=scenario_name,
            scenario_type=scenario_type.value,
            target_surface=target_surface.value,
        )
        return record

    def get_record(self, record_id: str) -> ScenarioRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        scenario_type: ScenarioType | None = None,
        target_surface: TargetSurface | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ScenarioRecord]:
        results = list(self._records)
        if scenario_type is not None:
            results = [r for r in results if r.scenario_type == scenario_type]
        if target_surface is not None:
            results = [r for r in results if r.target_surface == target_surface]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        scenario_name: str,
        scenario_type: ScenarioType = ScenarioType.PROMPT_INJECTION,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ScenarioAnalysis:
        analysis = ScenarioAnalysis(
            scenario_name=scenario_name,
            scenario_type=scenario_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "adversarial_scenario_generator_engine.analysis_added",
            scenario_name=scenario_name,
            scenario_type=scenario_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_scenario_coverage(self) -> list[dict[str, Any]]:
        """Analyze defense coverage across scenario types."""
        type_data: dict[str, list[ScenarioRecord]] = {}
        for r in self._records:
            type_data.setdefault(r.scenario_type.value, []).append(r)
        results: list[dict[str, Any]] = []
        for stype, records in type_data.items():
            coverages = [r.defense_coverage for r in records]
            avg_cov = round(sum(coverages) / len(coverages), 2) if coverages else 0.0
            high_risk = sum(1 for r in records if r.defense_coverage < self._threshold)
            results.append(
                {
                    "scenario_type": stype,
                    "total_scenarios": len(records),
                    "avg_defense_coverage": avg_cov,
                    "high_risk_count": high_risk,
                    "coverage_grade": "excellent"
                    if avg_cov >= 90
                    else "good"
                    if avg_cov >= self._threshold
                    else "fair"
                    if avg_cov >= 50
                    else "poor",
                }
            )
        return sorted(results, key=lambda x: x["avg_defense_coverage"])

    def identify_undefended_surfaces(self) -> list[dict[str, Any]]:
        """Identify target surfaces with insufficient defense coverage."""
        surface_data: dict[str, list[ScenarioRecord]] = {}
        for r in self._records:
            surface_data.setdefault(r.target_surface.value, []).append(r)
        results: list[dict[str, Any]] = []
        for surface, records in surface_data.items():
            coverages = [r.defense_coverage for r in records]
            avg_cov = round(sum(coverages) / len(coverages), 2) if coverages else 0.0
            probs = [r.success_probability for r in records]
            avg_prob = round(sum(probs) / len(probs), 2) if probs else 0.0
            if avg_cov < self._threshold:
                results.append(
                    {
                        "target_surface": surface,
                        "total_scenarios": len(records),
                        "avg_defense_coverage": avg_cov,
                        "avg_success_probability": avg_prob,
                        "severity": "critical"
                        if avg_cov < 30
                        else "high"
                        if avg_cov < 50
                        else "medium",
                    }
                )
        return sorted(results, key=lambda x: x["avg_defense_coverage"])

    def detect_threat_evolution(self) -> list[dict[str, Any]]:
        """Detect how threat scenarios evolve over time by complexity."""
        complexity_data: dict[str, list[ScenarioRecord]] = {}
        for r in self._records:
            complexity_data.setdefault(r.scenario_complexity.value, []).append(r)
        results: list[dict[str, Any]] = []
        for complexity, records in complexity_data.items():
            sorted_recs = sorted(records, key=lambda x: x.created_at)
            if len(sorted_recs) < 2:
                continue
            mid = len(sorted_recs) // 2
            first_half = sorted_recs[:mid]
            second_half = sorted_recs[mid:]
            avg_first = round(
                sum(r.success_probability for r in first_half) / len(first_half),
                2,
            )
            avg_second = round(
                sum(r.success_probability for r in second_half) / len(second_half),
                2,
            )
            delta = round(avg_second - avg_first, 2)
            results.append(
                {
                    "complexity": complexity,
                    "scenario_count": len(records),
                    "early_avg_success": avg_first,
                    "recent_avg_success": avg_second,
                    "delta": delta,
                    "trend": "escalating"
                    if delta > 5
                    else "stable"
                    if delta > -5
                    else "diminishing",
                }
            )
        return sorted(results, key=lambda x: x["delta"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.scenario_name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        coverages = [r.defense_coverage for r in matched]
        avg = round(sum(coverages) / len(coverages), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_defense_coverage": avg,
            "below_threshold": sum(1 for c in coverages if c < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> ScenarioReport:
        by_type: dict[str, int] = {}
        by_surface: dict[str, int] = {}
        by_complexity: dict[str, int] = {}
        for r in self._records:
            by_type[r.scenario_type.value] = by_type.get(r.scenario_type.value, 0) + 1
            by_surface[r.target_surface.value] = by_surface.get(r.target_surface.value, 0) + 1
            by_complexity[r.scenario_complexity.value] = (
                by_complexity.get(r.scenario_complexity.value, 0) + 1
            )
        high_risk_count = sum(1 for r in self._records if r.defense_coverage < self._threshold)
        probs = [r.success_probability for r in self._records]
        avg_prob = round(sum(probs) / len(probs), 2) if probs else 0.0
        undefended = self.identify_undefended_surfaces()
        top_undefended = [u["target_surface"] for u in undefended[:5]]
        recs: list[str] = []
        if self._records and high_risk_count > 0:
            recs.append(
                f"{high_risk_count} scenario(s) below coverage threshold ({self._threshold}%)"
            )
        if self._records and avg_prob > 50:
            recs.append(
                f"Avg success probability {avg_prob}% is high — defenses need strengthening"
            )
        if not recs:
            recs.append("Adversarial Scenario Generator Engine is healthy")
        return ScenarioReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            high_risk_count=high_risk_count,
            avg_success_probability=avg_prob,
            by_type=by_type,
            by_surface=by_surface,
            by_complexity=by_complexity,
            top_undefended=top_undefended,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("adversarial_scenario_generator_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for r in self._records:
            key = r.scenario_type.value
            type_dist[key] = type_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "coverage_threshold": self._threshold,
            "type_distribution": type_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
