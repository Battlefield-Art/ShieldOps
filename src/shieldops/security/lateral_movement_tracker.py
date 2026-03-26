"""Lateral Movement Tracker — track lateral movement patterns."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MovementTechnique(StrEnum):
    PASS_THE_HASH = "pass_the_hash"  # noqa: S105
    PASS_THE_TICKET = "pass_the_ticket"  # noqa: S105
    REMOTE_EXEC = "remote_exec"
    SSH_HIJACK = "ssh_hijack"
    RDP_SESSION = "rdp_session"


class HopRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DetectionStatus(StrEnum):
    DETECTED = "detected"
    BLOCKED = "blocked"
    MISSED = "missed"
    PARTIAL = "partial"
    SIMULATED = "simulated"


# --- Models ---


class MovementRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_id: str = ""
    technique: MovementTechnique = MovementTechnique.REMOTE_EXEC
    hop_risk: HopRisk = HopRisk.MEDIUM
    status: DetectionStatus = DetectionStatus.DETECTED
    source_host: str = ""
    target_host: str = ""
    hop_count: int = 0
    credential_used: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class MovementAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    campaign_id: str = ""
    technique: MovementTechnique = MovementTechnique.REMOTE_EXEC
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MovementReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_hop_count: float = 0.0
    detection_rate: float = 0.0
    by_technique: dict[str, int] = Field(default_factory=dict)
    by_risk: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class LateralMovementTracker:
    """Track lateral movement patterns."""

    def __init__(
        self,
        max_records: int = 200000,
        detection_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._detection_threshold = detection_threshold
        self._records: list[MovementRecord] = []
        self._analyses: list[MovementAnalysis] = []
        logger.info(
            "lateral_movement_tracker.init",
            max_records=max_records,
        )

    # -- record --

    def add_record(
        self,
        campaign_id: str = "",
        technique: MovementTechnique = (MovementTechnique.REMOTE_EXEC),
        hop_risk: HopRisk = HopRisk.MEDIUM,
        status: DetectionStatus = (DetectionStatus.DETECTED),
        source_host: str = "",
        target_host: str = "",
        hop_count: int = 0,
        credential_used: str = "",
        service: str = "",
        team: str = "",
    ) -> MovementRecord:
        record = MovementRecord(
            campaign_id=campaign_id,
            technique=technique,
            hop_risk=hop_risk,
            status=status,
            source_host=source_host,
            target_host=target_host,
            hop_count=hop_count,
            credential_used=credential_used,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "lateral_movement.record_added",
            record_id=record.id,
        )
        return record

    # -- process --

    def process(self, campaign_id: str) -> MovementAnalysis:
        relevant = [r for r in self._records if r.campaign_id == campaign_id]
        if not relevant:
            analysis = MovementAnalysis(
                campaign_id=campaign_id,
                description="no records found",
            )
            self._analyses.append(analysis)
            return analysis
        detected = sum(
            1
            for r in relevant
            if r.status
            in (
                DetectionStatus.DETECTED,
                DetectionStatus.BLOCKED,
            )
        )
        rate = (detected / len(relevant)) * 100
        breached = rate < self._detection_threshold
        analysis = MovementAnalysis(
            campaign_id=campaign_id,
            analysis_score=round(rate, 2),
            threshold=self._detection_threshold,
            breached=breached,
            description=(f"detection_rate={round(rate, 2)}%"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain methods --

    def track_movement_path(
        self,
    ) -> dict[str, Any]:
        """Movement paths by technique."""
        tech_data: dict[str, list[int]] = {}
        for r in self._records:
            key = r.technique.value
            tech_data.setdefault(key, []).append(r.hop_count)
        result: dict[str, Any] = {}
        for tech, hops in tech_data.items():
            result[tech] = {
                "count": len(hops),
                "avg_hops": round(sum(hops) / len(hops), 2),
                "max_hops": max(hops),
            }
        return result

    def identify_pivot_hosts(
        self,
    ) -> list[dict[str, Any]]:
        """Find frequently targeted hosts."""
        host_counts: dict[str, int] = {}
        for r in self._records:
            if r.target_host:
                host_counts[r.target_host] = host_counts.get(r.target_host, 0) + 1
        results: list[dict[str, Any]] = []
        for host, count in host_counts.items():
            results.append(
                {
                    "host": host,
                    "times_targeted": count,
                    "risk": ("high" if count > 3 else "low"),
                }
            )
        return sorted(
            results,
            key=lambda x: x["times_targeted"],
            reverse=True,
        )

    def analyze_credential_reuse(
        self,
    ) -> list[dict[str, Any]]:
        """Detect credential reuse across hops."""
        cred_hosts: dict[str, set[str]] = {}
        for r in self._records:
            if r.credential_used:
                cred_hosts.setdefault(r.credential_used, set()).add(r.target_host)
        results: list[dict[str, Any]] = []
        for cred, hosts in cred_hosts.items():
            if len(hosts) > 1:
                results.append(
                    {
                        "credential": cred,
                        "host_count": len(hosts),
                        "risk": "credential_reuse",
                    }
                )
        return sorted(
            results,
            key=lambda x: x["host_count"],
            reverse=True,
        )

    # -- report / stats --

    def generate_report(self) -> MovementReport:
        by_tech: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for r in self._records:
            by_tech[r.technique.value] = by_tech.get(r.technique.value, 0) + 1
            by_risk[r.hop_risk.value] = by_risk.get(r.hop_risk.value, 0) + 1
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
        hops = [r.hop_count for r in self._records]
        avg_hops = round(sum(hops) / len(hops), 2) if hops else 0.0
        detected = sum(
            1
            for r in self._records
            if r.status
            in (
                DetectionStatus.DETECTED,
                DetectionStatus.BLOCKED,
            )
        )
        det_rate = (
            round(
                detected / len(self._records) * 100,
                2,
            )
            if self._records
            else 0.0
        )
        recs: list[str] = []
        if det_rate < self._detection_threshold:
            recs.append(f"Detection rate {det_rate}% below {self._detection_threshold}%")
        if not recs:
            recs.append("Lateral movement tracking healthy")
        return MovementReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_hop_count=avg_hops,
            detection_rate=det_rate,
            by_technique=by_tech,
            by_risk=by_risk,
            by_status=by_status,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "detection_threshold": (self._detection_threshold),
            "unique_campaigns": len({r.campaign_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("lateral_movement_tracker.cleared")
        return {"status": "cleared"}
