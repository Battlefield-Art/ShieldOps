"""Identity Lateral Movement Engine — track identity-based lateral movement detection."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MovementVector(StrEnum):
    OAUTH_PIVOT = "oauth_pivot"
    SERVICE_ACCOUNT_CHAIN = "service_account_chain"
    FEDERATION_HOP = "federation_hop"
    DELEGATION_ABUSE = "delegation_abuse"
    CREDENTIAL_RELAY = "credential_relay"


class DetectionConfidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


class MovementScope(StrEnum):
    SINGLE_CLOUD = "single_cloud"
    CROSS_CLOUD = "cross_cloud"
    HYBRID = "hybrid"
    ON_PREM = "on_prem"


# --- Models ---


class IdentityLateralMovementRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    movement_vector: MovementVector = MovementVector.OAUTH_PIVOT
    detection_confidence: DetectionConfidence = DetectionConfidence.MEDIUM
    movement_scope: MovementScope = MovementScope.SINGLE_CLOUD
    source_identity: str = ""
    target_identity: str = ""
    hops: int = 0
    time_span_minutes: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class IdentityLateralMovementAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    movement_vector: MovementVector = MovementVector.OAUTH_PIVOT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IdentityLateralMovementReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_hops: float = 0.0
    by_movement_vector: dict[str, int] = Field(default_factory=dict)
    by_detection_confidence: dict[str, int] = Field(default_factory=dict)
    by_movement_scope: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class IdentityLateralMovementEngine:
    """Track identity-based lateral movement detection across environments."""

    def __init__(
        self,
        max_records: int = 200000,
        confidence_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = confidence_threshold
        self._records: list[IdentityLateralMovementRecord] = []
        self._analyses: list[IdentityLateralMovementAnalysis] = []
        logger.info(
            "identity_lateral_movement_engine.initialized",
            max_records=max_records,
            confidence_threshold=confidence_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        incident_id: str,
        movement_vector: MovementVector = MovementVector.OAUTH_PIVOT,
        detection_confidence: DetectionConfidence = DetectionConfidence.MEDIUM,
        movement_scope: MovementScope = MovementScope.SINGLE_CLOUD,
        source_identity: str = "",
        target_identity: str = "",
        hops: int = 0,
        time_span_minutes: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> IdentityLateralMovementRecord:
        record = IdentityLateralMovementRecord(
            incident_id=incident_id,
            movement_vector=movement_vector,
            detection_confidence=detection_confidence,
            movement_scope=movement_scope,
            source_identity=source_identity,
            target_identity=target_identity,
            hops=hops,
            time_span_minutes=time_span_minutes,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "identity_lateral_movement_engine.record_added",
            record_id=record.id,
            incident_id=incident_id,
            movement_vector=movement_vector.value,
            detection_confidence=detection_confidence.value,
        )
        return record

    def get_record(self, record_id: str) -> IdentityLateralMovementRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        movement_vector: MovementVector | None = None,
        detection_confidence: DetectionConfidence | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[IdentityLateralMovementRecord]:
        results = list(self._records)
        if movement_vector is not None:
            results = [r for r in results if r.movement_vector == movement_vector]
        if detection_confidence is not None:
            results = [r for r in results if r.detection_confidence == detection_confidence]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        incident_id: str,
        movement_vector: MovementVector = MovementVector.OAUTH_PIVOT,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> IdentityLateralMovementAnalysis:
        analysis = IdentityLateralMovementAnalysis(
            incident_id=incident_id,
            movement_vector=movement_vector,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "identity_lateral_movement_engine.analysis_added",
            incident_id=incident_id,
            movement_vector=movement_vector.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_movement_patterns(self) -> dict[str, Any]:
        """Analyze lateral movement patterns by vector and scope."""
        vector_data: dict[str, list[int]] = {}
        for r in self._records:
            key = r.movement_vector.value
            vector_data.setdefault(key, []).append(r.hops)
        result: dict[str, Any] = {}
        for vector, hops_list in vector_data.items():
            result[vector] = {
                "count": len(hops_list),
                "avg_hops": round(sum(hops_list) / len(hops_list), 2),
                "max_hops": max(hops_list),
                "above_threshold": any(h > self._threshold for h in hops_list),
            }
        return result

    def identify_high_risk_paths(self) -> list[dict[str, Any]]:
        """Identify high-risk lateral movement paths (confirmed/high confidence)."""
        high_risk: list[dict[str, Any]] = []
        for r in self._records:
            if r.detection_confidence in (
                DetectionConfidence.CONFIRMED,
                DetectionConfidence.HIGH,
            ):
                high_risk.append(
                    {
                        "record_id": r.id,
                        "incident_id": r.incident_id,
                        "movement_vector": r.movement_vector.value,
                        "detection_confidence": r.detection_confidence.value,
                        "movement_scope": r.movement_scope.value,
                        "source_identity": r.source_identity,
                        "target_identity": r.target_identity,
                        "hops": r.hops,
                        "time_span_minutes": r.time_span_minutes,
                    }
                )
        return sorted(high_risk, key=lambda x: x["hops"], reverse=True)

    def detect_movement_trends(self) -> list[dict[str, Any]]:
        """Detect trends in lateral movement detections over time."""
        buckets: dict[str, list[IdentityLateralMovementRecord]] = {}
        for r in self._records:
            day = time.strftime("%Y-%m-%d", time.gmtime(r.created_at))
            buckets.setdefault(day, []).append(r)
        trends: list[dict[str, Any]] = []
        for day, records in sorted(buckets.items()):
            confirmed_ct = sum(
                1 for r in records if r.detection_confidence == DetectionConfidence.CONFIRMED
            )
            cross_cloud_ct = sum(
                1 for r in records if r.movement_scope == MovementScope.CROSS_CLOUD
            )
            trends.append(
                {
                    "date": day,
                    "total_detections": len(records),
                    "confirmed": confirmed_ct,
                    "cross_cloud": cross_cloud_ct,
                }
            )
        return trends

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> IdentityLateralMovementReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.movement_vector.value] = by_e1.get(r.movement_vector.value, 0) + 1
            by_e2[r.detection_confidence.value] = by_e2.get(r.detection_confidence.value, 0) + 1
            by_e3[r.movement_scope.value] = by_e3.get(r.movement_scope.value, 0) + 1
        hops_list = [r.hops for r in self._records]
        avg_hops = round(sum(hops_list) / len(hops_list), 2) if hops_list else 0.0
        gap_count = sum(
            1
            for r in self._records
            if r.detection_confidence in (DetectionConfidence.CONFIRMED, DetectionConfidence.HIGH)
        )
        gap_list = self.identify_high_risk_paths()
        top_gaps = [o["incident_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} high-risk lateral movement path(s) detected")
        if not recs:
            recs.append("Identity Lateral Movement Engine is healthy")
        return IdentityLateralMovementReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_hops=avg_hops,
            by_movement_vector=by_e1,
            by_detection_confidence=by_e2,
            by_movement_scope=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("identity_lateral_movement_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.movement_vector.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "movement_vector_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
