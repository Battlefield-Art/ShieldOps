"""RiskTimelineEngine — track risk score evolution over time per entity."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TimelineGranularity(StrEnum):
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"


class TrendDirection(StrEnum):
    RISING = "rising"
    FALLING = "falling"
    STABLE = "stable"
    VOLATILE = "volatile"


class RiskPhase(StrEnum):
    BASELINE = "baseline"
    ESCALATION = "escalation"
    PEAK = "peak"
    RECOVERY = "recovery"


# --- Models ---


class RiskTimelineRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    timeline_granularity: TimelineGranularity = TimelineGranularity.HOUR
    trend_direction: TrendDirection = TrendDirection.STABLE
    risk_phase: RiskPhase = RiskPhase.BASELINE
    score: float = 0.0
    risk_score: float = 0.0
    entity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskTimelineAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    trend_direction: TrendDirection = TrendDirection.STABLE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskTimelineReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_timeline_granularity: dict[str, int] = Field(default_factory=dict)
    by_trend_direction: dict[str, int] = Field(default_factory=dict)
    by_risk_phase: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class RiskTimelineEngine:
    """Track risk score evolution over time per entity."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[RiskTimelineRecord] = []
        self._analyses: list[RiskTimelineAnalysis] = []
        logger.info(
            "risk_timeline_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        timeline_granularity: TimelineGranularity = TimelineGranularity.HOUR,
        trend_direction: TrendDirection = TrendDirection.STABLE,
        risk_phase: RiskPhase = RiskPhase.BASELINE,
        score: float = 0.0,
        risk_score: float = 0.0,
        entity: str = "",
        service: str = "",
        team: str = "",
    ) -> RiskTimelineRecord:
        record = RiskTimelineRecord(
            name=name,
            timeline_granularity=timeline_granularity,
            trend_direction=trend_direction,
            risk_phase=risk_phase,
            score=score,
            risk_score=risk_score,
            entity=entity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "risk_timeline_engine.record_added",
            record_id=record.id,
            name=name,
            trend_direction=trend_direction.value,
            risk_phase=risk_phase.value,
        )
        return record

    def get_record(self, record_id: str) -> RiskTimelineRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        trend_direction: TrendDirection | None = None,
        risk_phase: RiskPhase | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[RiskTimelineRecord]:
        results = list(self._records)
        if trend_direction is not None:
            results = [r for r in results if r.trend_direction == trend_direction]
        if risk_phase is not None:
            results = [r for r in results if r.risk_phase == risk_phase]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        trend_direction: TrendDirection = TrendDirection.STABLE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> RiskTimelineAnalysis:
        analysis = RiskTimelineAnalysis(
            name=name,
            trend_direction=trend_direction,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "risk_timeline_engine.analysis_added",
            name=name,
            trend_direction=trend_direction.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_risk_trajectory(self) -> list[dict[str, Any]]:
        """Compute risk trajectory per entity over time."""
        entity_data: dict[str, list[RiskTimelineRecord]] = {}
        for r in self._records:
            entity_data.setdefault(r.entity, []).append(r)
        results: list[dict[str, Any]] = []
        for entity, records in entity_data.items():
            risk_scores = [r.risk_score for r in records]
            if len(risk_scores) < 2:
                trajectory = "insufficient_data"
                delta = 0.0
            else:
                mid = len(risk_scores) // 2
                first_avg = sum(risk_scores[:mid]) / mid
                second_avg = sum(risk_scores[mid:]) / len(risk_scores[mid:])
                delta = round(second_avg - first_avg, 2)
                if abs(delta) < 5.0:
                    trajectory = "stable"
                elif delta > 0:
                    trajectory = "escalating"
                else:
                    trajectory = "recovering"
            results.append(
                {
                    "entity": entity,
                    "trajectory": trajectory,
                    "delta": delta,
                    "data_points": len(risk_scores),
                    "latest_risk_score": round(risk_scores[-1], 2),
                    "max_risk_score": round(max(risk_scores), 2),
                }
            )
        return sorted(results, key=lambda x: x["latest_risk_score"], reverse=True)

    def identify_risk_inflection_points(self) -> list[dict[str, Any]]:
        """Find points where risk trend significantly changed direction."""
        inflections: list[dict[str, Any]] = []
        entity_data: dict[str, list[RiskTimelineRecord]] = {}
        for r in self._records:
            entity_data.setdefault(r.entity, []).append(r)
        for entity, records in entity_data.items():
            if len(records) < 3:
                continue
            for i in range(1, len(records) - 1):
                prev_delta = records[i].risk_score - records[i - 1].risk_score
                next_delta = records[i + 1].risk_score - records[i].risk_score
                # Inflection: sign change with magnitude
                if prev_delta * next_delta < 0 and (abs(prev_delta) > 5.0 or abs(next_delta) > 5.0):
                    inflections.append(
                        {
                            "entity": entity,
                            "record_id": records[i].id,
                            "risk_score": records[i].risk_score,
                            "prev_delta": round(prev_delta, 2),
                            "next_delta": round(next_delta, 2),
                            "inflection_type": ("peak" if prev_delta > 0 else "trough"),
                        }
                    )
        return inflections

    def predict_risk_trend(self) -> list[dict[str, Any]]:
        """Predict near-term risk trend per entity using simple linear projection."""
        predictions: list[dict[str, Any]] = []
        entity_data: dict[str, list[RiskTimelineRecord]] = {}
        for r in self._records:
            entity_data.setdefault(r.entity, []).append(r)
        for entity, records in entity_data.items():
            if len(records) < 3:
                predictions.append(
                    {
                        "entity": entity,
                        "predicted_direction": "unknown",
                        "confidence": 0.0,
                        "data_points": len(records),
                    }
                )
                continue
            recent = records[-3:]
            deltas = [
                recent[i + 1].risk_score - recent[i].risk_score for i in range(len(recent) - 1)
            ]
            avg_delta = sum(deltas) / len(deltas)
            if avg_delta > 2.0:
                direction = "rising"
                confidence = min(0.9, abs(avg_delta) / 20.0)
            elif avg_delta < -2.0:
                direction = "falling"
                confidence = min(0.9, abs(avg_delta) / 20.0)
            else:
                direction = "stable"
                confidence = 0.7
            predicted_score = round(records[-1].risk_score + avg_delta, 2)
            predictions.append(
                {
                    "entity": entity,
                    "predicted_direction": direction,
                    "predicted_score": max(0.0, predicted_score),
                    "confidence": round(confidence, 2),
                    "data_points": len(records),
                }
            )
        return sorted(predictions, key=lambda x: x["confidence"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.trend_direction.value
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
                        "trend_direction": r.trend_direction.value,
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

    def generate_report(self) -> RiskTimelineReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.timeline_granularity.value] = by_e1.get(r.timeline_granularity.value, 0) + 1
            by_e2[r.trend_direction.value] = by_e2.get(r.trend_direction.value, 0) + 1
            by_e3[r.risk_phase.value] = by_e3.get(r.risk_phase.value, 0) + 1
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
            recs.append("Risk Timeline Engine is healthy")
        return RiskTimelineReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_timeline_granularity=by_e1,
            by_trend_direction=by_e2,
            by_risk_phase=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("risk_timeline_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.trend_direction.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "trend_direction_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
