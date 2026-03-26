"""AgentCommunicationAuditor — Audits agent-to-agent communication channels."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ChannelType(StrEnum):
    DIRECT = "direct"
    BROADCAST = "broadcast"
    DELEGATED = "delegated"
    PROXIED = "proxied"


class AuditVerdict(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    TAMPERED = "tampered"
    BLOCKED = "blocked"


class DataSensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


# --- Models ---


class CommunicationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str = ""
    destination: str = ""
    channel_type: ChannelType = ChannelType.DIRECT
    audit_verdict: AuditVerdict = AuditVerdict.CLEAN
    data_sensitivity: DataSensitivity = DataSensitivity.PUBLIC
    score: float = 0.0
    payload_size_bytes: int = 0
    message_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CommunicationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    channel_type: ChannelType = ChannelType.DIRECT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CommunicationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_channel_type: dict[str, int] = Field(default_factory=dict)
    by_audit_verdict: dict[str, int] = Field(default_factory=dict)
    by_data_sensitivity: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentCommunicationAuditor:
    """Audits agent-to-agent communication channels."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[CommunicationRecord] = []
        self._analyses: list[CommunicationAnalysis] = []
        logger.info(
            "agent_communication_auditor.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        source: str,
        destination: str,
        channel_type: ChannelType = ChannelType.DIRECT,
        audit_verdict: AuditVerdict = AuditVerdict.CLEAN,
        data_sensitivity: DataSensitivity = DataSensitivity.PUBLIC,
        score: float = 0.0,
        payload_size_bytes: int = 0,
        message_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> CommunicationRecord:
        record = CommunicationRecord(
            source=source,
            destination=destination,
            channel_type=channel_type,
            audit_verdict=audit_verdict,
            data_sensitivity=data_sensitivity,
            score=score,
            payload_size_bytes=payload_size_bytes,
            message_count=message_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_communication_auditor.record_added",
            record_id=record.id,
            source=source,
            destination=destination,
            channel_type=channel_type.value,
        )
        return record

    def get_record(self, record_id: str) -> CommunicationRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        channel_type: ChannelType | None = None,
        audit_verdict: AuditVerdict | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CommunicationRecord]:
        results = list(self._records)
        if channel_type is not None:
            results = [r for r in results if r.channel_type == channel_type]
        if audit_verdict is not None:
            results = [r for r in results if r.audit_verdict == audit_verdict]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        channel_type: ChannelType = ChannelType.DIRECT,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CommunicationAnalysis:
        analysis = CommunicationAnalysis(
            name=name,
            channel_type=channel_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "agent_communication_auditor.analysis_added",
            name=name,
            channel_type=channel_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def detect_data_leakage(self) -> list[dict[str, Any]]:
        """Detect potential data leakage via sensitive data on insecure channels."""
        leakage: list[dict[str, Any]] = []
        high_sensitivity = {DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED}
        insecure_channels = {ChannelType.BROADCAST, ChannelType.PROXIED}
        for r in self._records:
            if r.data_sensitivity in high_sensitivity and r.channel_type in insecure_channels:
                leakage.append(
                    {
                        "record_id": r.id,
                        "source": r.source,
                        "destination": r.destination,
                        "channel_type": r.channel_type.value,
                        "data_sensitivity": r.data_sensitivity.value,
                        "payload_size_bytes": r.payload_size_bytes,
                        "risk": "high",
                    }
                )
            elif r.audit_verdict == AuditVerdict.TAMPERED:
                leakage.append(
                    {
                        "record_id": r.id,
                        "source": r.source,
                        "destination": r.destination,
                        "channel_type": r.channel_type.value,
                        "data_sensitivity": r.data_sensitivity.value,
                        "payload_size_bytes": r.payload_size_bytes,
                        "risk": "critical",
                    }
                )
        return sorted(
            leakage,
            key=lambda x: 0 if x["risk"] == "critical" else 1,
        )

    def verify_message_integrity(self) -> list[dict[str, Any]]:
        """Verify message integrity across communication channels."""
        results: list[dict[str, Any]] = []
        channel_data: dict[str, list[CommunicationRecord]] = {}
        for r in self._records:
            key = f"{r.source}->{r.destination}"
            channel_data.setdefault(key, []).append(r)
        for channel, records in channel_data.items():
            tampered = sum(1 for r in records if r.audit_verdict == AuditVerdict.TAMPERED)
            blocked = sum(1 for r in records if r.audit_verdict == AuditVerdict.BLOCKED)
            total = len(records)
            integrity_pct = round((1 - (tampered + blocked) / total) * 100, 2) if total else 100.0
            results.append(
                {
                    "channel": channel,
                    "total_messages": total,
                    "tampered_count": tampered,
                    "blocked_count": blocked,
                    "integrity_percentage": integrity_pct,
                    "status": "compromised" if integrity_pct < 90 else "healthy",
                }
            )
        return sorted(results, key=lambda x: x["integrity_percentage"])

    def analyze_communication_patterns(self) -> list[dict[str, Any]]:
        """Analyze communication patterns to detect anomalous agent behavior."""
        agent_comms: dict[str, dict[str, Any]] = {}
        for r in self._records:
            if r.source not in agent_comms:
                agent_comms[r.source] = {
                    "destinations": set(),
                    "total_bytes": 0,
                    "total_messages": 0,
                    "channels_used": set(),
                    "verdicts": [],
                }
            data = agent_comms[r.source]
            data["destinations"].add(r.destination)
            data["total_bytes"] += r.payload_size_bytes
            data["total_messages"] += r.message_count
            data["channels_used"].add(r.channel_type.value)
            data["verdicts"].append(r.audit_verdict)
        results: list[dict[str, Any]] = []
        for agent, data in agent_comms.items():
            suspicious = sum(
                1 for v in data["verdicts"] if v in (AuditVerdict.SUSPICIOUS, AuditVerdict.TAMPERED)
            )
            total = len(data["verdicts"])
            anomaly_rate = round(suspicious / total * 100, 2) if total else 0.0
            results.append(
                {
                    "agent": agent,
                    "unique_destinations": len(data["destinations"]),
                    "total_bytes_sent": data["total_bytes"],
                    "total_messages": data["total_messages"],
                    "channels_used": sorted(data["channels_used"]),
                    "anomaly_rate_pct": anomaly_rate,
                    "status": "anomalous" if anomaly_rate > 20 else "normal",
                }
            )
        return sorted(results, key=lambda x: x["anomaly_rate_pct"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.channel_type.value
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
                        "source": r.source,
                        "destination": r.destination,
                        "channel_type": r.channel_type.value,
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

    def process(self, channel_id: str) -> dict[str, Any]:
        matched = [
            r
            for r in self._records
            if r.source == channel_id or r.destination == channel_id or r.service == channel_id
        ]
        if not matched:
            return {"key": channel_id, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": channel_id,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> CommunicationReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.channel_type.value] = by_e1.get(r.channel_type.value, 0) + 1
            by_e2[r.audit_verdict.value] = by_e2.get(r.audit_verdict.value, 0) + 1
            by_e3[r.data_sensitivity.value] = by_e3.get(r.data_sensitivity.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["source"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Agent Communication Auditor is healthy")
        return CommunicationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_channel_type=by_e1,
            by_audit_verdict=by_e2,
            by_data_sensitivity=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("agent_communication_auditor.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.channel_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "channel_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
