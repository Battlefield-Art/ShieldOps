"""NISTAIRMFEngine — NIST AI Risk Management Framework compliance tracking."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RMFFunction(StrEnum):
    GOVERN = "govern"
    MAP = "map"
    MEASURE = "measure"
    MANAGE = "manage"


class RMFCategory(StrEnum):
    GOVERNANCE = "governance"
    RISK_MAPPING = "risk_mapping"
    MEASUREMENT = "measurement"
    RISK_MANAGEMENT = "risk_management"


class MaturityLevel(StrEnum):
    INITIAL = "initial"
    DEVELOPING = "developing"
    DEFINED = "defined"
    MANAGED = "managed"
    OPTIMIZING = "optimizing"


# --- Models ---


class RMFRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    system_id: str = ""
    function: RMFFunction = RMFFunction.GOVERN
    category: RMFCategory = RMFCategory.GOVERNANCE
    maturity_level: MaturityLevel = MaturityLevel.INITIAL
    score: float = 0.0
    control_ref: str = ""
    evidence_ref: str = ""
    assessor: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class RMFAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    function: RMFFunction = RMFFunction.GOVERN
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RMFReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_function: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_maturity_level: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class NISTAIRMFEngine:
    """NIST AI Risk Management Framework compliance tracking."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[RMFRecord] = []
        self._analyses: list[RMFAnalysis] = []
        logger.info(
            "nist_ai_rmf_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        system_id: str,
        function: RMFFunction = RMFFunction.GOVERN,
        category: RMFCategory = RMFCategory.GOVERNANCE,
        maturity_level: MaturityLevel = MaturityLevel.INITIAL,
        score: float = 0.0,
        control_ref: str = "",
        evidence_ref: str = "",
        assessor: str = "",
        service: str = "",
        team: str = "",
    ) -> RMFRecord:
        record = RMFRecord(
            system_id=system_id,
            function=function,
            category=category,
            maturity_level=maturity_level,
            score=score,
            control_ref=control_ref,
            evidence_ref=evidence_ref,
            assessor=assessor,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "nist_ai_rmf_engine.record_added",
            record_id=record.id,
            system_id=system_id,
            function=function.value,
            category=category.value,
        )
        return record

    def get_record(self, record_id: str) -> RMFRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        function: RMFFunction | None = None,
        category: RMFCategory | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[RMFRecord]:
        results = list(self._records)
        if function is not None:
            results = [r for r in results if r.function == function]
        if category is not None:
            results = [r for r in results if r.category == category]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        function: RMFFunction = RMFFunction.GOVERN,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> RMFAnalysis:
        analysis = RMFAnalysis(
            name=name,
            function=function,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "nist_ai_rmf_engine.analysis_added",
            name=name,
            function=function.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def assess_function_maturity(self) -> list[dict[str, Any]]:
        """Assess maturity level per RMF function across all systems."""
        maturity_order = {
            MaturityLevel.INITIAL: 1,
            MaturityLevel.DEVELOPING: 2,
            MaturityLevel.DEFINED: 3,
            MaturityLevel.MANAGED: 4,
            MaturityLevel.OPTIMIZING: 5,
        }
        function_data: dict[str, list[RMFRecord]] = {}
        for r in self._records:
            function_data.setdefault(r.function.value, []).append(r)
        results: list[dict[str, Any]] = []
        for func, records in function_data.items():
            maturity_scores = [maturity_order.get(r.maturity_level, 1) for r in records]
            avg_maturity = round(sum(maturity_scores) / len(maturity_scores), 2)
            scores = [r.score for r in records]
            avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
            maturity_dist: dict[str, int] = {}
            for r in records:
                maturity_dist[r.maturity_level.value] = (
                    maturity_dist.get(r.maturity_level.value, 0) + 1
                )
            results.append(
                {
                    "function": func,
                    "systems_assessed": len({r.system_id for r in records}),
                    "avg_maturity_score": avg_maturity,
                    "avg_compliance_score": avg_score,
                    "maturity_distribution": maturity_dist,
                    "target_maturity": "managed",
                    "gap_to_target": round(max(0, 4 - avg_maturity), 2),
                }
            )
        return sorted(results, key=lambda x: x["avg_maturity_score"])

    def identify_gaps(self) -> list[dict[str, Any]]:
        """Identify compliance gaps where scores fall below threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "system_id": r.system_id,
                        "function": r.function.value,
                        "category": r.category.value,
                        "maturity_level": r.maturity_level.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def generate_action_plan(self) -> list[dict[str, Any]]:
        """Generate prioritized action plan to improve RMF maturity."""
        maturity_order = {
            MaturityLevel.INITIAL: 1,
            MaturityLevel.DEVELOPING: 2,
            MaturityLevel.DEFINED: 3,
            MaturityLevel.MANAGED: 4,
            MaturityLevel.OPTIMIZING: 5,
        }
        system_data: dict[str, list[RMFRecord]] = {}
        for r in self._records:
            system_data.setdefault(r.system_id, []).append(r)
        actions: list[dict[str, Any]] = []
        for system_id, records in system_data.items():
            for r in records:
                current = maturity_order.get(r.maturity_level, 1)
                if current < 4:  # Below "managed" target
                    target_level = list(maturity_order.keys())[
                        min(current, len(maturity_order) - 1)
                    ]
                    priority = (
                        "critical" if current <= 1 else ("high" if current == 2 else "medium")
                    )
                    actions.append(
                        {
                            "system_id": system_id,
                            "function": r.function.value,
                            "category": r.category.value,
                            "current_maturity": r.maturity_level.value,
                            "target_maturity": target_level.value,
                            "current_score": r.score,
                            "priority": priority,
                            "action": (
                                f"Advance {r.function.value}/{r.category.value} from "
                                f"{r.maturity_level.value} to {target_level.value}"
                            ),
                        }
                    )
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        return sorted(actions, key=lambda x: priority_order.get(x["priority"], 99))

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.function.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

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

    def process(self, system_id: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.system_id == system_id]
        if not matched:
            return {"key": system_id, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": system_id,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> RMFReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.function.value] = by_e1.get(r.function.value, 0) + 1
            by_e2[r.category.value] = by_e2.get(r.category.value, 0) + 1
            by_e3[r.maturity_level.value] = by_e3.get(r.maturity_level.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["system_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("NIST AI RMF Engine is healthy")
        return RMFReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_function=by_e1,
            by_category=by_e2,
            by_maturity_level=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("nist_ai_rmf_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.function.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "function_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
