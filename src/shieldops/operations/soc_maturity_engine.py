"""SOC Maturity Engine — assess SOC maturity dimensions."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MaturityDimension(StrEnum):
    DETECTION = "detection"
    RESPONSE = "response"
    AUTOMATION = "automation"
    THREAT_INTEL = "threat_intel"
    GOVERNANCE = "governance"


class MaturityLevel(StrEnum):
    INITIAL = "initial"
    MANAGED = "managed"
    DEFINED = "defined"
    MEASURED = "measured"
    OPTIMIZED = "optimized"


class TransformationPhase(StrEnum):
    ASSESSMENT = "assessment"
    PLANNING = "planning"
    IMPLEMENTATION = "implementation"
    VALIDATION = "validation"
    OPTIMIZATION = "optimization"


# --- Models ---


class MaturityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    dimension: MaturityDimension = MaturityDimension.DETECTION
    level: MaturityLevel = MaturityLevel.INITIAL
    phase: TransformationPhase = TransformationPhase.ASSESSMENT
    score: float = 0.0
    target_score: float = 0.0
    assessor: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class MaturityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    dimension: MaturityDimension = MaturityDimension.DETECTION
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MaturityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    overall_maturity: float = 0.0
    by_dimension: dict[str, int] = Field(default_factory=dict)
    by_level: dict[str, int] = Field(default_factory=dict)
    by_phase: dict[str, int] = Field(default_factory=dict)
    dimension_scores: dict[str, float] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class SocMaturityEngine:
    """Assess SOC maturity across dimensions."""

    def __init__(
        self,
        max_records: int = 200000,
        maturity_threshold: float = 3.0,
    ) -> None:
        self._max_records = max_records
        self._maturity_threshold = maturity_threshold
        self._records: list[MaturityRecord] = []
        self._analyses: list[MaturityAnalysis] = []
        logger.info(
            "soc_maturity_engine.init",
            max_records=max_records,
        )

    # -- record --

    def add_record(
        self,
        dimension: MaturityDimension = (MaturityDimension.DETECTION),
        level: MaturityLevel = (MaturityLevel.INITIAL),
        phase: TransformationPhase = (TransformationPhase.ASSESSMENT),
        score: float = 0.0,
        target_score: float = 0.0,
        assessor: str = "",
        service: str = "",
        team: str = "",
    ) -> MaturityRecord:
        record = MaturityRecord(
            dimension=dimension,
            level=level,
            phase=phase,
            score=score,
            target_score=target_score,
            assessor=assessor,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "soc_maturity.record_added",
            record_id=record.id,
        )
        return record

    # -- process --

    def process(self, dimension: str) -> MaturityAnalysis:
        relevant = [r for r in self._records if r.dimension.value == dimension]
        if not relevant:
            analysis = MaturityAnalysis(
                description="no records found",
            )
            self._analyses.append(analysis)
            return analysis
        scores = [r.score for r in relevant]
        avg = sum(scores) / len(scores)
        breached = avg < self._maturity_threshold
        analysis = MaturityAnalysis(
            analysis_score=round(avg, 2),
            threshold=self._maturity_threshold,
            breached=breached,
            description=(f"avg_score={round(avg, 2)}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain methods --

    def assess_dimension(
        self,
    ) -> dict[str, Any]:
        """Latest score per dimension."""
        dim_scores: dict[str, float] = {}
        for r in self._records:
            dim_scores[r.dimension.value] = r.score
        return {"dimensions": {k: round(v, 2) for k, v in dim_scores.items()}}

    def calculate_overall_maturity(
        self,
    ) -> dict[str, Any]:
        """Weighted average across dimensions."""
        dim_latest: dict[str, float] = {}
        for r in self._records:
            dim_latest[r.dimension.value] = r.score
        if not dim_latest:
            return {
                "overall": 0.0,
                "dimensions": 0,
            }
        avg = sum(dim_latest.values()) / len(dim_latest)
        return {
            "overall": round(avg, 2),
            "dimensions": len(dim_latest),
            "scores": {k: round(v, 2) for k, v in dim_latest.items()},
        }

    def generate_roadmap(
        self,
    ) -> list[dict[str, Any]]:
        """Roadmap items for below-threshold dims."""
        dim_data: dict[str, list[float]] = {}
        for r in self._records:
            dim_data.setdefault(r.dimension.value, []).append(r.score)
        roadmap: list[dict[str, Any]] = []
        for dim, scores in dim_data.items():
            avg = sum(scores) / len(scores)
            if avg < self._maturity_threshold:
                gap = round(
                    self._maturity_threshold - avg,
                    2,
                )
                roadmap.append(
                    {
                        "dimension": dim,
                        "current": round(avg, 2),
                        "target": (self._maturity_threshold),
                        "gap": gap,
                        "priority": ("high" if gap > 1.0 else "medium"),
                    }
                )
        return sorted(
            roadmap,
            key=lambda x: x["gap"],
            reverse=True,
        )

    # -- report / stats --

    def generate_report(self) -> MaturityReport:
        by_dim: dict[str, int] = {}
        by_lvl: dict[str, int] = {}
        by_ph: dict[str, int] = {}
        for r in self._records:
            by_dim[r.dimension.value] = by_dim.get(r.dimension.value, 0) + 1
            by_lvl[r.level.value] = by_lvl.get(r.level.value, 0) + 1
            by_ph[r.phase.value] = by_ph.get(r.phase.value, 0) + 1
        maturity = self.calculate_overall_maturity()
        overall = maturity.get("overall", 0.0)
        dim_scores = maturity.get("scores", {})
        recs: list[str] = []
        roadmap = self.generate_roadmap()
        for item in roadmap[:3]:
            recs.append(f"{item['dimension']}: gap {item['gap']} to target")
        if not recs:
            recs.append("SOC maturity meets thresholds")
        return MaturityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            overall_maturity=overall,
            by_dimension=by_dim,
            by_level=by_lvl,
            by_phase=by_ph,
            dimension_scores=dim_scores,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "maturity_threshold": (self._maturity_threshold),
            "unique_dimensions": len({r.dimension.value for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("soc_maturity_engine.cleared")
        return {"status": "cleared"}
