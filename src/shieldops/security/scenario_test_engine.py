"""Scenario Test Engine — run and evaluate control tests."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TestComplexity(StrEnum):
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    ADVANCED = "advanced"


class ControlCategory(StrEnum):
    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    DETERRENT = "deterrent"
    COMPENSATING = "compensating"


class RegressionType(StrEnum):
    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"
    NEW_BYPASS = "new_bypass"


# --- Models ---


class ScenarioRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario_name: str = ""
    complexity: TestComplexity = TestComplexity.SIMPLE
    category: ControlCategory = ControlCategory.DETECTIVE
    regression: RegressionType = RegressionType.NONE
    score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ScenarioAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario_name: str = ""
    complexity: TestComplexity = TestComplexity.SIMPLE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ScenarioReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_score: float = 0.0
    by_complexity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_regression: dict[str, int] = Field(default_factory=dict)
    regressions: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ScenarioTestEngine:
    """Run scenario tests and evaluate controls."""

    def __init__(
        self,
        max_records: int = 200000,
        pass_threshold: float = 70.0,
    ) -> None:
        self._max = max_records
        self._pass_threshold = pass_threshold
        self._records: list[ScenarioRecord] = []
        self._analyses: list[ScenarioAnalysis] = []
        logger.info(
            "scenario_test_engine.initialized",
            max_records=max_records,
        )

    def add_record(
        self,
        scenario_name: str = "",
        complexity: TestComplexity = (TestComplexity.SIMPLE),
        category: ControlCategory = (ControlCategory.DETECTIVE),
        regression: RegressionType = (RegressionType.NONE),
        score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ScenarioRecord:
        rec = ScenarioRecord(
            scenario_name=scenario_name,
            complexity=complexity,
            category=category,
            regression=regression,
            score=score,
            service=service,
            team=team,
        )
        self._records.append(rec)
        if len(self._records) > self._max:
            self._records = self._records[-self._max :]
        logger.info(
            "scenario_test_engine.record_added",
            record_id=rec.id,
        )
        return rec

    def process(self, key: str) -> ScenarioAnalysis:
        matches = [r for r in self._records if r.scenario_name == key]
        total = sum(r.score for r in matches)
        avg = total / len(matches) if matches else 0.0
        analysis = ScenarioAnalysis(
            scenario_name=key,
            analysis_score=round(avg, 2),
            threshold=self._pass_threshold,
            breached=avg < self._pass_threshold,
            description=f"Tested {len(matches)} records",
        )
        self._analyses.append(analysis)
        return analysis

    # -- domain methods ---

    def run_test_step(
        self,
        scenario: str,
        step: str,
    ) -> dict[str, Any]:
        """Execute a single test step."""
        matches = [r for r in self._records if r.scenario_name == scenario]
        return {
            "scenario": scenario,
            "step": step,
            "records_matched": len(matches),
            "status": "executed",
        }

    def evaluate_control(
        self,
        category: ControlCategory = (ControlCategory.DETECTIVE),
    ) -> dict[str, Any]:
        """Evaluate controls of a given category."""
        matches = [r for r in self._records if r.category == category]
        if not matches:
            return {
                "category": category.value,
                "avg": 0.0,
            }
        avg = sum(r.score for r in matches) / len(matches)
        return {
            "category": category.value,
            "count": len(matches),
            "avg_score": round(avg, 2),
        }

    def detect_regression(self) -> list[dict[str, Any]]:
        """Find records with non-none regression."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.regression != RegressionType.NONE:
                results.append(
                    {
                        "id": r.id,
                        "scenario": r.scenario_name,
                        "regression": r.regression.value,
                        "score": r.score,
                    }
                )
        return results

    # -- report / stats ---

    def generate_report(self) -> ScenarioReport:
        by_complexity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_regression: dict[str, int] = {}
        for r in self._records:
            cx = r.complexity.value
            by_complexity[cx] = by_complexity.get(cx, 0) + 1
            ct = r.category.value
            by_category[ct] = by_category.get(ct, 0) + 1
            rg = r.regression.value
            by_regression[rg] = by_regression.get(rg, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        regs = [r.scenario_name for r in self._records if r.regression != RegressionType.NONE][:5]
        recs: list[str] = []
        if regs:
            recs.append(f"{len(regs)} scenario(s) show regression")
        if not recs:
            recs.append("All scenarios passing")
        return ScenarioReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_score=avg,
            by_complexity=by_complexity,
            by_category=by_category,
            by_regression=by_regression,
            regressions=regs,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        dist: dict[str, int] = {}
        for r in self._records:
            k = r.category.value
            dist[k] = dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "pass_threshold": self._pass_threshold,
            "category_distribution": dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("scenario_test_engine.cleared")
        return {"status": "cleared"}
