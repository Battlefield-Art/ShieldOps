"""Data Flow Tracker — track data flows for DLP."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class FlowDirection(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"
    CROSS_CLOUD = "cross_cloud"
    EXTERNAL = "external"


class SurfaceType(StrEnum):
    API = "api"
    DATABASE = "database"
    OBJECT_STORE = "object_store"
    MESSAGE_QUEUE = "message_queue"
    AI_PIPELINE = "ai_pipeline"


class SensitivityLevel(StrEnum):
    TOP_SECRET = "top_secret"  # noqa: S105
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"
    UNCLASSIFIED = "unclassified"


# --- Models ---


class DataFlowRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    flow_id: str = ""
    direction: FlowDirection = FlowDirection.INTERNAL
    surface: SurfaceType = SurfaceType.API
    sensitivity: SensitivityLevel = SensitivityLevel.INTERNAL
    source_system: str = ""
    target_system: str = ""
    volume_bytes: int = 0
    anomalous: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class DataFlowAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    flow_id: str = ""
    direction: FlowDirection = FlowDirection.INTERNAL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DataFlowReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    total_volume_bytes: int = 0
    anomalous_count: int = 0
    by_direction: dict[str, int] = Field(default_factory=dict)
    by_surface: dict[str, int] = Field(default_factory=dict)
    by_sensitivity: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class DataFlowTracker:
    """Track data flows across surfaces for DLP."""

    def __init__(
        self,
        max_records: int = 200000,
        anomaly_threshold: float = 10.0,
    ) -> None:
        self._max_records = max_records
        self._anomaly_threshold = anomaly_threshold
        self._records: list[DataFlowRecord] = []
        self._analyses: list[DataFlowAnalysis] = []
        logger.info(
            "data_flow_tracker.init",
            max_records=max_records,
        )

    # -- record --

    def add_record(
        self,
        flow_id: str = "",
        direction: FlowDirection = (FlowDirection.INTERNAL),
        surface: SurfaceType = SurfaceType.API,
        sensitivity: SensitivityLevel = (SensitivityLevel.INTERNAL),
        source_system: str = "",
        target_system: str = "",
        volume_bytes: int = 0,
        anomalous: bool = False,
        service: str = "",
        team: str = "",
    ) -> DataFlowRecord:
        record = DataFlowRecord(
            flow_id=flow_id,
            direction=direction,
            surface=surface,
            sensitivity=sensitivity,
            source_system=source_system,
            target_system=target_system,
            volume_bytes=volume_bytes,
            anomalous=anomalous,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "data_flow_tracker.record_added",
            record_id=record.id,
        )
        return record

    # -- process --

    def process(self, flow_id: str) -> DataFlowAnalysis:
        relevant = [r for r in self._records if r.flow_id == flow_id]
        if not relevant:
            analysis = DataFlowAnalysis(
                flow_id=flow_id,
                description="no records found",
            )
            self._analyses.append(analysis)
            return analysis
        anomalous = sum(1 for r in relevant if r.anomalous)
        rate = (anomalous / len(relevant)) * 100
        breached = rate > self._anomaly_threshold
        analysis = DataFlowAnalysis(
            flow_id=flow_id,
            analysis_score=round(rate, 2),
            threshold=self._anomaly_threshold,
            breached=breached,
            description=(f"anomaly_rate={round(rate, 2)}%"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain methods --

    def map_data_flow(self) -> dict[str, Any]:
        """Map flows by source -> target."""
        flow_map: dict[str, int] = {}
        for r in self._records:
            key = f"{r.source_system}->{r.target_system}"
            flow_map[key] = flow_map.get(key, 0) + 1
        return {"flows": flow_map}

    def detect_anomalous_flow(
        self,
    ) -> list[dict[str, Any]]:
        """List anomalous flows by sensitivity."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.anomalous:
                results.append(
                    {
                        "flow_id": r.flow_id,
                        "direction": (r.direction.value),
                        "sensitivity": (r.sensitivity.value),
                        "volume_bytes": (r.volume_bytes),
                        "source": (r.source_system),
                        "target": (r.target_system),
                    }
                )
        return sorted(
            results,
            key=lambda x: x["volume_bytes"],
            reverse=True,
        )

    def classify_flow_risk(
        self,
    ) -> dict[str, Any]:
        """Risk classification by sensitivity."""
        sens_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.sensitivity.value
            sens_data.setdefault(
                key,
                {
                    "total": 0,
                    "anomalous": 0,
                    "outbound": 0,
                },
            )
            sens_data[key]["total"] += 1
            if r.anomalous:
                sens_data[key]["anomalous"] += 1
            if r.direction in (
                FlowDirection.OUTBOUND,
                FlowDirection.EXTERNAL,
            ):
                sens_data[key]["outbound"] += 1
        result: dict[str, Any] = {}
        for sens, data in sens_data.items():
            risk = "low"
            if sens in ("top_secret", "confidential") and data["outbound"] > 0:
                risk = "critical"
            elif data["anomalous"] > 0:
                risk = "high"
            result[sens] = {
                "total": data["total"],
                "anomalous": data["anomalous"],
                "outbound": data["outbound"],
                "risk": risk,
            }
        return result

    # -- report / stats --

    def generate_report(self) -> DataFlowReport:
        by_d: dict[str, int] = {}
        by_s: dict[str, int] = {}
        by_sens: dict[str, int] = {}
        for r in self._records:
            by_d[r.direction.value] = by_d.get(r.direction.value, 0) + 1
            by_s[r.surface.value] = by_s.get(r.surface.value, 0) + 1
            by_sens[r.sensitivity.value] = by_sens.get(r.sensitivity.value, 0) + 1
        total_vol = sum(r.volume_bytes for r in self._records)
        anom = sum(1 for r in self._records if r.anomalous)
        recs: list[str] = []
        if anom > 0:
            recs.append(f"{anom} anomalous flows detected")
        sensitive_out = sum(
            1
            for r in self._records
            if r.sensitivity
            in (
                SensitivityLevel.TOP_SECRET,
                SensitivityLevel.CONFIDENTIAL,
            )
            and r.direction
            in (
                FlowDirection.OUTBOUND,
                FlowDirection.EXTERNAL,
            )
        )
        if sensitive_out > 0:
            recs.append(f"{sensitive_out} sensitive outbound flows")
        if not recs:
            recs.append("Data flow posture is healthy")
        return DataFlowReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            total_volume_bytes=total_vol,
            anomalous_count=anom,
            by_direction=by_d,
            by_surface=by_s,
            by_sensitivity=by_sens,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "anomaly_threshold": (self._anomaly_threshold),
            "unique_flows": len({r.flow_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("data_flow_tracker.cleared")
        return {"status": "cleared"}
