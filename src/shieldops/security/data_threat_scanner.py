"""Data Threat Scanner — scan data stores for threats."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ScanTarget(StrEnum):
    DATABASE = "database"
    OBJECT_STORAGE = "object_storage"
    FILE_SYSTEM = "file_system"
    BACKUP_ARCHIVE = "backup_archive"
    SNAPSHOT = "snapshot"


class ThreatCategory(StrEnum):
    RANSOMWARE = "ransomware"
    BACKDOOR = "backdoor"
    DATA_EXFIL_TOOL = "data_exfil_tool"
    CRYPTOMINER = "cryptominer"
    DORMANT_IMPLANT = "dormant_implant"


class ScanDepth(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    FORENSIC = "forensic"
    CONTINUOUS = "continuous"


# --- Models ---


class DataThreatRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""
    target: ScanTarget = ScanTarget.DATABASE
    category: ThreatCategory = ThreatCategory.RANSOMWARE
    depth: ScanDepth = ScanDepth.STANDARD
    target_path: str = ""
    threats_detected: int = 0
    files_scanned: int = 0
    dormant_days: int = 0
    risk_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class DataThreatAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = ""
    target: ScanTarget = ScanTarget.DATABASE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DataThreatReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    total_threats: int = 0
    total_files_scanned: int = 0
    by_target: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_depth: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class DataThreatScanner:
    """Scan data stores for dormant threats."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 0.7,
    ) -> None:
        self._max_records = max_records
        self._threshold = risk_threshold
        self._records: list[DataThreatRecord] = []
        self._analyses: list[DataThreatAnalysis] = []
        logger.info(
            "data_threat_scanner.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        scan_id: str,
        target: ScanTarget = ScanTarget.DATABASE,
        category: ThreatCategory = (ThreatCategory.RANSOMWARE),
        depth: ScanDepth = ScanDepth.STANDARD,
        target_path: str = "",
        threats_detected: int = 0,
        files_scanned: int = 0,
        dormant_days: int = 0,
        risk_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> DataThreatRecord:
        record = DataThreatRecord(
            scan_id=scan_id,
            target=target,
            category=category,
            depth=depth,
            target_path=target_path,
            threats_detected=threats_detected,
            files_scanned=files_scanned,
            dormant_days=dormant_days,
            risk_score=risk_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "data_threat_scanner.record_added",
            record_id=record.id,
            scan_id=scan_id,
            target=target.value,
            category=category.value,
        )
        return record

    def get_record(self, record_id: str) -> DataThreatRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        target: ScanTarget | None = None,
        category: ThreatCategory | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[DataThreatRecord]:
        results = list(self._records)
        if target is not None:
            results = [r for r in results if r.target == target]
        if category is not None:
            results = [r for r in results if r.category == category]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, scan_id: str) -> DataThreatAnalysis:
        matched = [r for r in self._records if r.scan_id == scan_id]
        scores = [r.risk_score for r in matched]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        breached = avg > self._threshold
        analysis = DataThreatAnalysis(
            scan_id=scan_id,
            target=(matched[-1].target if matched else ScanTarget.DATABASE),
            analysis_score=avg,
            threshold=self._threshold,
            breached=breached,
            description=(f"Avg risk {avg} for {scan_id}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "data_threat_scanner.processed",
            scan_id=scan_id,
            avg_risk=avg,
            breached=breached,
        )
        return analysis

    # -- domain operations ------------------------------------

    def scan_for_threats(
        self,
        scan_id: str,
        target: ScanTarget,
        target_path: str = "",
        depth: ScanDepth = ScanDepth.STANDARD,
    ) -> dict[str, Any]:
        """Scan a data store for threats."""
        record = self.add_record(
            scan_id=scan_id,
            target=target,
            target_path=target_path,
            depth=depth,
        )
        analysis = self.process(scan_id)
        return {
            "record_id": record.id,
            "scan_id": scan_id,
            "target": target.value,
            "target_path": target_path,
            "depth": depth.value,
            "analysis_score": analysis.analysis_score,
            "breached": analysis.breached,
        }

    def analyze_dormant_malware(
        self,
    ) -> list[dict[str, Any]]:
        """Analyze dormant malware across scans."""
        dormant = [r for r in self._records if r.dormant_days > 0]
        results: list[dict[str, Any]] = []
        for r in dormant:
            results.append(
                {
                    "record_id": r.id,
                    "scan_id": r.scan_id,
                    "target": r.target.value,
                    "category": r.category.value,
                    "dormant_days": r.dormant_days,
                    "risk_score": r.risk_score,
                    "target_path": r.target_path,
                }
            )
        results.sort(
            key=lambda x: x["dormant_days"],
            reverse=True,
        )
        return results

    def correlate_across_snapshots(
        self,
    ) -> dict[str, Any]:
        """Correlate threats across snapshots."""
        snapshot_records = [
            r
            for r in self._records
            if r.target
            in (
                ScanTarget.SNAPSHOT,
                ScanTarget.BACKUP_ARCHIVE,
            )
        ]
        by_path: dict[str, list[str]] = {}
        for r in snapshot_records:
            by_path.setdefault(r.target_path, []).append(r.category.value)
        recurring: dict[str, list[str]] = {}
        for path, cats in by_path.items():
            if len(cats) > 1:
                recurring[path] = cats
        return {
            "total_snapshots_scanned": len(snapshot_records),
            "unique_paths": len(by_path),
            "recurring_threats": len(recurring),
            "recurring_details": recurring,
        }

    # -- report / stats ----------------------------------------

    def generate_report(self) -> DataThreatReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.target.value] = by_e1.get(r.target.value, 0) + 1
            by_e2[r.category.value] = by_e2.get(r.category.value, 0) + 1
            by_e3[r.depth.value] = by_e3.get(r.depth.value, 0) + 1
        total_threats = sum(r.threats_detected for r in self._records)
        total_files = sum(r.files_scanned for r in self._records)
        gap_count = sum(1 for r in self._records if r.risk_score > self._threshold)
        top_gaps = [r.scan_id for r in self._records if r.risk_score > self._threshold][:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} high-risk scan(s)")
        if total_threats > 0:
            recs.append(f"{total_threats} total threat(s)")
        if not recs:
            recs.append("Data Threat Scanner is healthy")
        return DataThreatReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            total_threats=total_threats,
            total_files_scanned=total_files,
            by_target=by_e1,
            by_category=by_e2,
            by_depth=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("data_threat_scanner.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.target.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "target_distribution": e1_dist,
            "unique_scans": len({r.scan_id for r in self._records}),
            "unique_teams": len({r.team for r in self._records}),
        }
