"""BlindSpotTracker -- track security blind spots."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BlindSpotType(StrEnum):
    DATA_SOURCE = "data_source"
    TECHNIQUE = "technique"
    ASSET = "asset"
    IDENTITY = "identity"
    NETWORK = "network"


class RiskImpact(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MitigationStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"


# --- Models ---


class BlindSpotRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    spot_type: BlindSpotType = BlindSpotType.DATA_SOURCE
    risk_impact: RiskImpact = RiskImpact.LOW
    mitigation: MitigationStatus = MitigationStatus.OPEN
    score: float = 0.0
    affected_area: str = ""
    description: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class BlindSpotAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    spot_type: BlindSpotType = BlindSpotType.DATA_SOURCE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class BlindSpotReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_spot_type: dict[str, int] = Field(default_factory=dict)
    by_risk_impact: dict[str, int] = Field(default_factory=dict)
    by_mitigation: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class BlindSpotTracker:
    """Track security blind spots and gaps."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[BlindSpotRecord] = []
        self._analyses: list[BlindSpotAnalysis] = []
        logger.info(
            "blind_spot_tracker.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    def add_record(
        self,
        name: str,
        spot_type: BlindSpotType = BlindSpotType.DATA_SOURCE,
        risk_impact: RiskImpact = RiskImpact.LOW,
        mitigation: MitigationStatus = MitigationStatus.OPEN,
        score: float = 0.0,
        affected_area: str = "",
        description: str = "",
        service: str = "",
        team: str = "",
    ) -> BlindSpotRecord:
        record = BlindSpotRecord(
            name=name,
            spot_type=spot_type,
            risk_impact=risk_impact,
            mitigation=mitigation,
            score=score,
            affected_area=affected_area,
            description=description,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "blind_spot_tracker.record_added",
            record_id=record.id,
            name=name,
        )
        return record

    def get_record(self, record_id: str) -> BlindSpotRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        spot_type: BlindSpotType | None = None,
        risk_impact: RiskImpact | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[BlindSpotRecord]:
        results = list(self._records)
        if spot_type is not None:
            results = [r for r in results if r.spot_type == spot_type]
        if risk_impact is not None:
            results = [r for r in results if r.risk_impact == risk_impact]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        spot_type: BlindSpotType = BlindSpotType.DATA_SOURCE,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> BlindSpotAnalysis:
        analysis = BlindSpotAnalysis(
            name=name,
            spot_type=spot_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ---

    def track_blind_spot(
        self,
    ) -> list[dict[str, Any]]:
        """Track blind spots by type."""
        type_data: dict[str, list[BlindSpotRecord]] = {}
        for r in self._records:
            type_data.setdefault(r.spot_type.value, []).append(r)
        results: list[dict[str, Any]] = []
        for stype, records in type_data.items():
            open_count = sum(1 for r in records if r.mitigation == MitigationStatus.OPEN)
            results.append(
                {
                    "type": stype,
                    "total": len(records),
                    "open": open_count,
                    "mitigated": len(records) - open_count,
                }
            )
        return sorted(
            results,
            key=lambda x: x["open"],
            reverse=True,
        )

    def assess_risk_impact(
        self,
    ) -> dict[str, Any]:
        """Assess risk impact distribution."""
        impact_scores: dict[str, list[float]] = {}
        for r in self._records:
            impact_scores.setdefault(r.risk_impact.value, []).append(r.score)
        assessment: dict[str, Any] = {}
        for impact, scores in impact_scores.items():
            avg = sum(scores) / len(scores)
            assessment[impact] = {
                "avg_score": round(avg, 2),
                "count": len(scores),
            }
        return assessment

    def recommend_mitigation(
        self,
    ) -> list[dict[str, Any]]:
        """Recommend mitigations for open spots."""
        recs: list[dict[str, Any]] = []
        for r in self._records:
            if r.mitigation == MitigationStatus.OPEN:
                recs.append(
                    {
                        "name": r.name,
                        "type": r.spot_type.value,
                        "risk": r.risk_impact.value,
                        "area": r.affected_area,
                        "score": r.score,
                    }
                )
        return sorted(
            recs,
            key=lambda x: x["score"],
            reverse=True,
        )

    # -- standard methods ---

    def identify_gaps(
        self,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "spot_type": r.spot_type.value,
                        "score": r.score,
                        "service": r.service,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    def generate_report(self) -> BlindSpotReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            v1 = r.spot_type.value
            by_e1[v1] = by_e1.get(v1, 0) + 1
            v2 = r.risk_impact.value
            by_e2[v2] = by_e2.get(v2, 0) + 1
            v3 = r.mitigation.value
            by_e3[v3] = by_e3.get(v3, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if not recs:
            recs.append("Blind Spot Tracker is healthy")
        return BlindSpotReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg,
            by_spot_type=by_e1,
            by_risk_impact=by_e2,
            by_mitigation=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("blind_spot_tracker.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.spot_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "spot_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
