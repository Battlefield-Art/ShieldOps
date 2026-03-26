"""Clean Room Validator — validate backup snapshots."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ScanResult(StrEnum):
    CLEAN = "clean"
    INFECTED = "infected"
    SUSPICIOUS = "suspicious"
    INCONCLUSIVE = "inconclusive"
    PENDING = "pending"


class MalwarePresence(StrEnum):
    NONE_DETECTED = "none_detected"
    ACTIVE_MALWARE = "active_malware"
    DORMANT_IMPLANT = "dormant_implant"
    PERSISTENCE_MECHANISM = "persistence_mechanism"
    ROOTKIT = "rootkit"


class ValidationMethod(StrEnum):
    HASH_COMPARISON = "hash_comparison"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    SIGNATURE_SCAN = "signature_scan"
    SANDBOX_EXECUTION = "sandbox_execution"
    INTEGRITY_CHECK = "integrity_check"


# --- Models ---


class CleanRoomRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    snapshot_id: str = ""
    scan_result: ScanResult = ScanResult.PENDING
    malware_presence: MalwarePresence = MalwarePresence.NONE_DETECTED
    method: ValidationMethod = ValidationMethod.SIGNATURE_SCAN
    source_system: str = ""
    snapshot_age_hours: float = 0.0
    threats_found: int = 0
    certified: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CleanRoomAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    snapshot_id: str = ""
    scan_result: ScanResult = ScanResult.PENDING
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CleanRoomReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    clean_rate_pct: float = 0.0
    certified_count: int = 0
    by_scan_result: dict[str, int] = Field(default_factory=dict)
    by_malware_presence: dict[str, int] = Field(default_factory=dict)
    by_method: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class CleanRoomValidator:
    """Validate backup snapshots in clean room."""

    def __init__(
        self,
        max_records: int = 200000,
        threat_threshold: float = 0.5,
    ) -> None:
        self._max_records = max_records
        self._threshold = threat_threshold
        self._records: list[CleanRoomRecord] = []
        self._analyses: list[CleanRoomAnalysis] = []
        logger.info(
            "clean_room_validator.initialized",
            max_records=max_records,
            threat_threshold=threat_threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        snapshot_id: str,
        scan_result: ScanResult = ScanResult.PENDING,
        malware_presence: MalwarePresence = (MalwarePresence.NONE_DETECTED),
        method: ValidationMethod = (ValidationMethod.SIGNATURE_SCAN),
        source_system: str = "",
        snapshot_age_hours: float = 0.0,
        threats_found: int = 0,
        certified: bool = False,
        service: str = "",
        team: str = "",
    ) -> CleanRoomRecord:
        record = CleanRoomRecord(
            snapshot_id=snapshot_id,
            scan_result=scan_result,
            malware_presence=malware_presence,
            method=method,
            source_system=source_system,
            snapshot_age_hours=snapshot_age_hours,
            threats_found=threats_found,
            certified=certified,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "clean_room_validator.record_added",
            record_id=record.id,
            snapshot_id=snapshot_id,
            scan_result=scan_result.value,
        )
        return record

    def get_record(self, record_id: str) -> CleanRoomRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        scan_result: ScanResult | None = None,
        method: ValidationMethod | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CleanRoomRecord]:
        results = list(self._records)
        if scan_result is not None:
            results = [r for r in results if r.scan_result == scan_result]
        if method is not None:
            results = [r for r in results if r.method == method]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, snapshot_id: str) -> CleanRoomAnalysis:
        matched = [r for r in self._records if r.snapshot_id == snapshot_id]
        threat_ct = sum(r.threats_found for r in matched)
        total = len(matched) if matched else 1
        score = round(threat_ct / total, 2)
        breached = score > self._threshold
        analysis = CleanRoomAnalysis(
            snapshot_id=snapshot_id,
            scan_result=(matched[-1].scan_result if matched else ScanResult.PENDING),
            analysis_score=score,
            threshold=self._threshold,
            breached=breached,
            description=(f"Threat score {score} for {snapshot_id}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "clean_room_validator.processed",
            snapshot_id=snapshot_id,
            score=score,
            breached=breached,
        )
        return analysis

    # -- domain operations ------------------------------------

    def validate_snapshot(
        self,
        snapshot_id: str,
        source_system: str = "",
        method: ValidationMethod = (ValidationMethod.SIGNATURE_SCAN),
    ) -> dict[str, Any]:
        """Validate a snapshot in clean room env."""
        record = self.add_record(
            snapshot_id=snapshot_id,
            source_system=source_system,
            method=method,
            scan_result=ScanResult.CLEAN,
            threats_found=0,
        )
        analysis = self.process(snapshot_id)
        return {
            "record_id": record.id,
            "snapshot_id": snapshot_id,
            "scan_result": record.scan_result.value,
            "method": method.value,
            "analysis_score": analysis.analysis_score,
            "breached": analysis.breached,
        }

    def detect_persistence(self, snapshot_id: str) -> dict[str, Any]:
        """Detect persistence mechanisms."""
        matched = [r for r in self._records if r.snapshot_id == snapshot_id]
        persistence_found = any(
            r.malware_presence == MalwarePresence.PERSISTENCE_MECHANISM for r in matched
        )
        rootkit_found = any(r.malware_presence == MalwarePresence.ROOTKIT for r in matched)
        dormant_found = any(r.malware_presence == MalwarePresence.DORMANT_IMPLANT for r in matched)
        risk_score = 0.0
        if persistence_found:
            risk_score += 0.4
        if rootkit_found:
            risk_score += 0.4
        if dormant_found:
            risk_score += 0.2
        return {
            "snapshot_id": snapshot_id,
            "records_checked": len(matched),
            "persistence_found": persistence_found,
            "rootkit_found": rootkit_found,
            "dormant_found": dormant_found,
            "risk_score": round(risk_score, 2),
        }

    def certify_clean(self, snapshot_id: str) -> dict[str, Any]:
        """Certify a snapshot as clean."""
        matched = [r for r in self._records if r.snapshot_id == snapshot_id]
        if not matched:
            return {
                "snapshot_id": snapshot_id,
                "certified": False,
                "reason": "no_records_found",
            }
        all_clean = all(r.scan_result == ScanResult.CLEAN for r in matched)
        no_malware = all(r.malware_presence == MalwarePresence.NONE_DETECTED for r in matched)
        can_certify = all_clean and no_malware
        if can_certify:
            for r in matched:
                r.certified = True
        return {
            "snapshot_id": snapshot_id,
            "certified": can_certify,
            "records_checked": len(matched),
            "all_clean": all_clean,
            "no_malware": no_malware,
        }

    # -- report / stats ----------------------------------------

    def generate_report(self) -> CleanRoomReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.scan_result.value] = by_e1.get(r.scan_result.value, 0) + 1
            by_e2[r.malware_presence.value] = by_e2.get(r.malware_presence.value, 0) + 1
            by_e3[r.method.value] = by_e3.get(r.method.value, 0) + 1
        total = len(self._records)
        clean_ct = sum(1 for r in self._records if r.scan_result == ScanResult.CLEAN)
        clean_rate = round(clean_ct / total * 100, 2) if total else 0.0
        certified_ct = sum(1 for r in self._records if r.certified)
        gap_count = sum(
            1
            for r in self._records
            if r.scan_result in (ScanResult.INFECTED, ScanResult.SUSPICIOUS)
        )
        top_gaps = [r.snapshot_id for r in self._records if r.scan_result == ScanResult.INFECTED][
            :5
        ]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} infected/suspicious snapshot(s)")
        if not recs:
            recs.append("Clean Room Validator is healthy")
        return CleanRoomReport(
            total_records=total,
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            clean_rate_pct=clean_rate,
            certified_count=certified_ct,
            by_scan_result=by_e1,
            by_malware_presence=by_e2,
            by_method=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("clean_room_validator.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.scan_result.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "scan_result_distribution": e1_dist,
            "certified_count": sum(1 for r in self._records if r.certified),
            "unique_snapshots": len({r.snapshot_id for r in self._records}),
        }
