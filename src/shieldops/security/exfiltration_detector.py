"""Exfiltration Detector — detect data exfiltration."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ExfilChannel(StrEnum):
    DNS_TUNNEL = "dns_tunnel"
    HTTPS_UPLOAD = "https_upload"
    CLOUD_STORAGE = "cloud_storage"
    EMAIL = "email"
    AI_PIPELINE = "ai_pipeline"


class DetectionMethod(StrEnum):
    VOLUME_ANOMALY = "volume_anomaly"
    PATTERN_MATCH = "pattern_match"
    BEHAVIOR_ANALYSIS = "behavior_analysis"
    DLP_SIGNATURE = "dlp_signature"
    ML_MODEL = "ml_model"


class ExfilSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --- Models ---


class ExfiltrationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    channel: ExfilChannel = ExfilChannel.HTTPS_UPLOAD
    method: DetectionMethod = DetectionMethod.VOLUME_ANOMALY
    severity: ExfilSeverity = ExfilSeverity.HIGH
    data_volume_bytes: int = 0
    source_entity: str = ""
    destination: str = ""
    ai_pipeline_involved: bool = False
    confidence: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ExfiltrationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    channel: ExfilChannel = ExfilChannel.HTTPS_UPLOAD
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ExfiltrationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    total_data_at_risk_bytes: int = 0
    ai_pipeline_incidents: int = 0
    by_channel: dict[str, int] = Field(default_factory=dict)
    by_method: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class ExfiltrationDetector:
    """Detect data exfiltration across channels."""

    def __init__(
        self,
        max_records: int = 200000,
        confidence_threshold: float = 0.7,
    ) -> None:
        self._max_records = max_records
        self._confidence_threshold = confidence_threshold
        self._records: list[ExfiltrationRecord] = []
        self._analyses: list[ExfiltrationAnalysis] = []
        logger.info(
            "exfiltration_detector.init",
            max_records=max_records,
        )

    # -- record --

    def add_record(
        self,
        incident_id: str = "",
        channel: ExfilChannel = (ExfilChannel.HTTPS_UPLOAD),
        method: DetectionMethod = (DetectionMethod.VOLUME_ANOMALY),
        severity: ExfilSeverity = (ExfilSeverity.HIGH),
        data_volume_bytes: int = 0,
        source_entity: str = "",
        destination: str = "",
        ai_pipeline_involved: bool = False,
        confidence: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> ExfiltrationRecord:
        record = ExfiltrationRecord(
            incident_id=incident_id,
            channel=channel,
            method=method,
            severity=severity,
            data_volume_bytes=data_volume_bytes,
            source_entity=source_entity,
            destination=destination,
            ai_pipeline_involved=(ai_pipeline_involved),
            confidence=confidence,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "exfiltration_detector.recorded",
            record_id=record.id,
        )
        return record

    # -- process --

    def process(self, incident_id: str) -> ExfiltrationAnalysis:
        relevant = [r for r in self._records if r.incident_id == incident_id]
        if not relevant:
            analysis = ExfiltrationAnalysis(
                incident_id=incident_id,
                description="no records found",
            )
            self._analyses.append(analysis)
            return analysis
        confs = [r.confidence for r in relevant]
        avg = sum(confs) / len(confs)
        breached = avg >= self._confidence_threshold
        analysis = ExfiltrationAnalysis(
            incident_id=incident_id,
            analysis_score=round(avg, 4),
            threshold=(self._confidence_threshold),
            breached=breached,
            description=(f"avg_confidence={round(avg, 4)}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain methods --

    def detect_exfiltration(
        self,
    ) -> dict[str, Any]:
        """Detection stats by channel."""
        chan_data: dict[str, dict[str, Any]] = {}
        for r in self._records:
            key = r.channel.value
            chan_data.setdefault(
                key,
                {
                    "count": 0,
                    "total_bytes": 0,
                },
            )
            chan_data[key]["count"] += 1
            chan_data[key]["total_bytes"] += r.data_volume_bytes
        return chan_data

    def analyze_ai_pipeline_leakage(
        self,
    ) -> list[dict[str, Any]]:
        """AI pipeline exfiltration events."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.ai_pipeline_involved:
                results.append(
                    {
                        "incident_id": (r.incident_id),
                        "channel": (r.channel.value),
                        "volume_bytes": (r.data_volume_bytes),
                        "confidence": (r.confidence),
                        "source": (r.source_entity),
                        "destination": (r.destination),
                    }
                )
        return sorted(
            results,
            key=lambda x: x["volume_bytes"],
            reverse=True,
        )

    def calculate_data_at_risk(
        self,
    ) -> dict[str, Any]:
        """Total data at risk by severity."""
        sev_data: dict[str, int] = {}
        for r in self._records:
            if r.confidence >= self._confidence_threshold:
                key = r.severity.value
                sev_data[key] = sev_data.get(key, 0) + r.data_volume_bytes
        total = sum(sev_data.values())
        return {
            "total_bytes": total,
            "by_severity": sev_data,
        }

    # -- report / stats --

    def generate_report(
        self,
    ) -> ExfiltrationReport:
        by_ch: dict[str, int] = {}
        by_m: dict[str, int] = {}
        by_s: dict[str, int] = {}
        for r in self._records:
            by_ch[r.channel.value] = by_ch.get(r.channel.value, 0) + 1
            by_m[r.method.value] = by_m.get(r.method.value, 0) + 1
            by_s[r.severity.value] = by_s.get(r.severity.value, 0) + 1
        total_bytes = sum(r.data_volume_bytes for r in self._records)
        ai_count = sum(1 for r in self._records if r.ai_pipeline_involved)
        recs: list[str] = []
        critical = sum(1 for r in self._records if r.severity == ExfilSeverity.CRITICAL)
        if critical > 0:
            recs.append(f"{critical} critical exfiltration events")
        if ai_count > 0:
            recs.append(f"{ai_count} AI pipeline leakage events")
        if not recs:
            recs.append("No exfiltration detected")
        return ExfiltrationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            total_data_at_risk_bytes=total_bytes,
            ai_pipeline_incidents=ai_count,
            by_channel=by_ch,
            by_method=by_m,
            by_severity=by_s,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "confidence_threshold": (self._confidence_threshold),
            "unique_incidents": len({r.incident_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("exfiltration_detector.cleared")
        return {"status": "cleared"}
