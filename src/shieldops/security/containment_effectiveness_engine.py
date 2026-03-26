"""Containment Effectiveness Engine —
measure containment action effectiveness,
track speed and completeness of threat isolation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ContainmentType(StrEnum):
    NETWORK_ISOLATION = "network_isolation"
    CREDENTIAL_REVOKE = "credential_revoke"
    PROCESS_KILL = "process_kill"
    QUARANTINE = "quarantine"
    ACCOUNT_DISABLE = "account_disable"


class EffectivenessRating(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    INEFFECTIVE = "ineffective"
    UNKNOWN = "unknown"
    OVERKILL = "overkill"


class ContainmentSpeed(StrEnum):
    IMMEDIATE = "immediate"
    FAST = "fast"
    MODERATE = "moderate"
    SLOW = "slow"
    MANUAL = "manual"


# --- Models ---


class ContainmentEffectivenessRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    containment_type: ContainmentType = ContainmentType.NETWORK_ISOLATION
    effectiveness_rating: EffectivenessRating = EffectivenessRating.COMPLETE
    containment_speed: ContainmentSpeed = ContainmentSpeed.FAST
    time_to_contain_seconds: float = 0.0
    lateral_movement_stopped: bool = True
    affected_systems: int = 0
    collateral_impact: int = 0
    threat_actor: str = ""
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ContainmentEffectivenessAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    containment_type: ContainmentType = ContainmentType.NETWORK_ISOLATION
    effectiveness_rating: EffectivenessRating = EffectivenessRating.COMPLETE
    avg_time_to_contain: float = 0.0
    success_rate: float = 0.0
    avg_collateral: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ContainmentEffectivenessReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_time_to_contain: float = 0.0
    by_containment_type: dict[str, int] = Field(default_factory=dict)
    by_effectiveness_rating: dict[str, int] = Field(default_factory=dict)
    by_containment_speed: dict[str, int] = Field(default_factory=dict)
    ineffective_incidents: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ContainmentEffectivenessEngine:
    """Measure containment action effectiveness,
    track speed and completeness of threat isolation."""

    def __init__(self, max_records: int = 200000, effectiveness_threshold: float = 85.0) -> None:
        self._max_records = max_records
        self._effectiveness_threshold = effectiveness_threshold
        self._records: list[ContainmentEffectivenessRecord] = []
        self._analyses: dict[str, ContainmentEffectivenessAnalysis] = {}
        logger.info(
            "containment_effectiveness_engine.init",
            max_records=max_records,
            effectiveness_threshold=effectiveness_threshold,
        )

    def add_record(
        self,
        incident_id: str = "",
        containment_type: ContainmentType = ContainmentType.NETWORK_ISOLATION,
        effectiveness_rating: EffectivenessRating = EffectivenessRating.COMPLETE,
        containment_speed: ContainmentSpeed = ContainmentSpeed.FAST,
        time_to_contain_seconds: float = 0.0,
        lateral_movement_stopped: bool = True,
        affected_systems: int = 0,
        collateral_impact: int = 0,
        threat_actor: str = "",
        description: str = "",
    ) -> ContainmentEffectivenessRecord:
        record = ContainmentEffectivenessRecord(
            incident_id=incident_id,
            containment_type=containment_type,
            effectiveness_rating=effectiveness_rating,
            containment_speed=containment_speed,
            time_to_contain_seconds=time_to_contain_seconds,
            lateral_movement_stopped=lateral_movement_stopped,
            affected_systems=affected_systems,
            collateral_impact=collateral_impact,
            threat_actor=threat_actor,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "containment_effectiveness.record_added",
            record_id=record.id,
            incident_id=incident_id,
        )
        return record

    def process(self, key: str) -> ContainmentEffectivenessAnalysis | dict[str, Any]:
        recs = [r for r in self._records if r.incident_id == key or r.id == key]
        if not recs:
            return {"status": "not_found", "key": key}
        avg_ttc = round(sum(r.time_to_contain_seconds for r in recs) / len(recs), 2)
        effective = sum(
            1
            for r in recs
            if r.effectiveness_rating
            in (EffectivenessRating.COMPLETE, EffectivenessRating.OVERKILL)
        )
        success_rate = round(effective / len(recs) * 100, 2)
        avg_collateral = round(sum(r.collateral_impact for r in recs) / len(recs), 2)
        analysis = ContainmentEffectivenessAnalysis(
            containment_type=recs[0].containment_type,
            effectiveness_rating=recs[0].effectiveness_rating,
            avg_time_to_contain=avg_ttc,
            success_rate=success_rate,
            avg_collateral=avg_collateral,
            description=(
                f"incident={key} avg_ttc={avg_ttc}s "
                f"success={success_rate}% collateral={avg_collateral}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> ContainmentEffectivenessReport:
        by_type: dict[str, int] = {}
        by_rating: dict[str, int] = {}
        by_speed: dict[str, int] = {}
        ttcs: list[float] = []
        for r in self._records:
            ct = r.containment_type.value
            by_type[ct] = by_type.get(ct, 0) + 1
            er = r.effectiveness_rating.value
            by_rating[er] = by_rating.get(er, 0) + 1
            cs = r.containment_speed.value
            by_speed[cs] = by_speed.get(cs, 0) + 1
            ttcs.append(r.time_to_contain_seconds)
        avg_ttc = round(sum(ttcs) / len(ttcs), 2) if ttcs else 0.0
        ineffective = list(
            {
                r.incident_id
                for r in self._records
                if r.effectiveness_rating == EffectivenessRating.INEFFECTIVE
            }
        )[:10]
        recs: list[str] = []
        if ineffective:
            recs.append(f"{len(ineffective)} incidents with ineffective containment")
        slow = by_speed.get("slow", 0) + by_speed.get("manual", 0)
        if slow > len(self._records) * 0.3:
            recs.append("High rate of slow/manual containment — increase automation")
        if not recs:
            recs.append("Containment effectiveness within acceptable bounds")
        return ContainmentEffectivenessReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_time_to_contain=avg_ttc,
            by_containment_type=by_type,
            by_effectiveness_rating=by_rating,
            by_containment_speed=by_speed,
            ineffective_incidents=ineffective,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        rating_dist: dict[str, int] = {}
        for r in self._records:
            k = r.effectiveness_rating.value
            rating_dist[k] = rating_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "rating_distribution": rating_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("containment_effectiveness_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def analyze_containment_by_type(self) -> list[dict[str, Any]]:
        """Analyze effectiveness metrics per containment type."""
        type_data: dict[str, list[ContainmentEffectivenessRecord]] = {}
        for r in self._records:
            type_data.setdefault(r.containment_type.value, []).append(r)
        results: list[dict[str, Any]] = []
        for ctype, recs in type_data.items():
            effective = sum(
                1 for r in recs if r.effectiveness_rating == EffectivenessRating.COMPLETE
            )
            avg_ttc = sum(r.time_to_contain_seconds for r in recs) / len(recs)
            results.append(
                {
                    "containment_type": ctype,
                    "total_actions": len(recs),
                    "effective_count": effective,
                    "effectiveness_pct": round(effective / len(recs) * 100, 2),
                    "avg_time_to_contain_s": round(avg_ttc, 2),
                }
            )
        results.sort(key=lambda x: x["effectiveness_pct"], reverse=True)
        return results

    def detect_lateral_movement_failures(self) -> list[dict[str, Any]]:
        """Detect containment actions that failed to stop lateral movement."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if not r.lateral_movement_stopped:
                results.append(
                    {
                        "incident_id": r.incident_id,
                        "containment_type": r.containment_type.value,
                        "effectiveness_rating": r.effectiveness_rating.value,
                        "time_to_contain_seconds": r.time_to_contain_seconds,
                        "affected_systems": r.affected_systems,
                        "threat_actor": r.threat_actor,
                    }
                )
        results.sort(key=lambda x: x["affected_systems"], reverse=True)
        return results

    def rank_incidents_by_response_quality(self) -> list[dict[str, Any]]:
        """Rank incidents by overall containment response quality."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            eff_score = {
                EffectivenessRating.COMPLETE: 100,
                EffectivenessRating.OVERKILL: 80,
                EffectivenessRating.PARTIAL: 50,
                EffectivenessRating.UNKNOWN: 25,
                EffectivenessRating.INEFFECTIVE: 0,
            }.get(r.effectiveness_rating, 0)
            speed_score = {
                ContainmentSpeed.IMMEDIATE: 100,
                ContainmentSpeed.FAST: 80,
                ContainmentSpeed.MODERATE: 50,
                ContainmentSpeed.SLOW: 25,
                ContainmentSpeed.MANUAL: 10,
            }.get(r.containment_speed, 0)
            lateral_bonus = 20 if r.lateral_movement_stopped else 0
            quality = round((eff_score * 0.5 + speed_score * 0.3 + lateral_bonus), 2)
            results.append(
                {
                    "incident_id": r.incident_id,
                    "containment_type": r.containment_type.value,
                    "effectiveness": r.effectiveness_rating.value,
                    "speed": r.containment_speed.value,
                    "quality_score": quality,
                    "rank": 0,
                }
            )
        results.sort(key=lambda x: x["quality_score"], reverse=True)
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
