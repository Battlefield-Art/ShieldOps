"""Evidence Collection Engine —
manage audit evidence lifecycle,
track freshness and completeness, ensure audit readiness."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EvidenceMethod(StrEnum):
    AUTOMATED = "automated"
    SEMI_AUTOMATED = "semi_automated"
    MANUAL = "manual"
    API_PULL = "api_pull"
    LOG_EXPORT = "log_export"


class EvidenceFreshness(StrEnum):
    CURRENT = "current"
    STALE = "stale"
    EXPIRED = "expired"
    MISSING = "missing"
    PENDING = "pending"


class AuditReadiness(StrEnum):
    READY = "ready"
    NEEDS_REVIEW = "needs_review"
    INCOMPLETE = "incomplete"
    OVERDUE = "overdue"
    EXEMPT = "exempt"


# --- Models ---


class EvidenceCollectionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_id: str = ""
    control_id: str = ""
    framework: str = ""
    evidence_method: EvidenceMethod = EvidenceMethod.AUTOMATED
    evidence_freshness: EvidenceFreshness = EvidenceFreshness.CURRENT
    audit_readiness: AuditReadiness = AuditReadiness.READY
    days_since_collected: float = 0.0
    file_size_kb: float = 0.0
    collector_name: str = ""
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class EvidenceCollectionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    control_id: str = ""
    framework: str = ""
    freshness_score: float = 0.0
    readiness_pct: float = 0.0
    stale_count: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class EvidenceCollectionReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    overall_readiness_pct: float = 0.0
    by_evidence_method: dict[str, int] = Field(default_factory=dict)
    by_evidence_freshness: dict[str, int] = Field(default_factory=dict)
    by_audit_readiness: dict[str, int] = Field(default_factory=dict)
    stale_evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class EvidenceCollectionEngine:
    """Manage audit evidence lifecycle,
    track freshness and completeness, ensure audit readiness."""

    def __init__(self, max_records: int = 200000, freshness_threshold: float = 7.0) -> None:
        self._max_records = max_records
        self._freshness_threshold = freshness_threshold
        self._records: list[EvidenceCollectionRecord] = []
        self._analyses: dict[str, EvidenceCollectionAnalysis] = {}
        logger.info(
            "evidence_collection_engine.init",
            max_records=max_records,
            freshness_threshold=freshness_threshold,
        )

    def add_record(
        self,
        evidence_id: str = "",
        control_id: str = "",
        framework: str = "",
        evidence_method: EvidenceMethod = EvidenceMethod.AUTOMATED,
        evidence_freshness: EvidenceFreshness = EvidenceFreshness.CURRENT,
        audit_readiness: AuditReadiness = AuditReadiness.READY,
        days_since_collected: float = 0.0,
        file_size_kb: float = 0.0,
        collector_name: str = "",
        description: str = "",
    ) -> EvidenceCollectionRecord:
        record = EvidenceCollectionRecord(
            evidence_id=evidence_id,
            control_id=control_id,
            framework=framework,
            evidence_method=evidence_method,
            evidence_freshness=evidence_freshness,
            audit_readiness=audit_readiness,
            days_since_collected=days_since_collected,
            file_size_kb=file_size_kb,
            collector_name=collector_name,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "evidence_collection.record_added",
            record_id=record.id,
            evidence_id=evidence_id,
        )
        return record

    def process(self, key: str) -> EvidenceCollectionAnalysis | dict[str, Any]:
        recs = [r for r in self._records if r.control_id == key or r.id == key]
        if not recs:
            return {"status": "not_found", "key": key}
        ready = sum(1 for r in recs if r.audit_readiness == AuditReadiness.READY)
        readiness_pct = round(ready / len(recs) * 100, 2)
        stale = sum(
            1
            for r in recs
            if r.evidence_freshness in (EvidenceFreshness.STALE, EvidenceFreshness.EXPIRED)
        )
        freshness = round(
            sum(1 for r in recs if r.evidence_freshness == EvidenceFreshness.CURRENT)
            / len(recs)
            * 100,
            2,
        )
        analysis = EvidenceCollectionAnalysis(
            control_id=recs[0].control_id,
            framework=recs[0].framework,
            freshness_score=freshness,
            readiness_pct=readiness_pct,
            stale_count=stale,
            description=(
                f"{recs[0].control_id} readiness={readiness_pct}% "
                f"freshness={freshness}% stale={stale}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> EvidenceCollectionReport:
        by_method: dict[str, int] = {}
        by_fresh: dict[str, int] = {}
        by_ready: dict[str, int] = {}
        for r in self._records:
            em = r.evidence_method.value
            by_method[em] = by_method.get(em, 0) + 1
            ef = r.evidence_freshness.value
            by_fresh[ef] = by_fresh.get(ef, 0) + 1
            ar = r.audit_readiness.value
            by_ready[ar] = by_ready.get(ar, 0) + 1
        ready_count = by_ready.get("ready", 0)
        total = len(self._records)
        overall = round(ready_count / total * 100, 2) if total else 0.0
        stale = list(
            {
                r.evidence_id
                for r in self._records
                if r.days_since_collected > self._freshness_threshold
            }
        )[:10]
        recs: list[str] = []
        if stale:
            recs.append(f"{len(stale)} evidence items older than {self._freshness_threshold} days")
        missing = by_fresh.get("missing", 0)
        if missing:
            recs.append(f"{missing} controls missing evidence — collect immediately")
        if not recs:
            recs.append("Evidence collection meets audit readiness requirements")
        return EvidenceCollectionReport(
            total_records=total,
            total_analyses=len(self._analyses),
            overall_readiness_pct=overall,
            by_evidence_method=by_method,
            by_evidence_freshness=by_fresh,
            by_audit_readiness=by_ready,
            stale_evidence=stale,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        freshness_dist: dict[str, int] = {}
        for r in self._records:
            k = r.evidence_freshness.value
            freshness_dist[k] = freshness_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "freshness_distribution": freshness_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("evidence_collection_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def find_stale_evidence(self) -> list[dict[str, Any]]:
        """Find evidence items that exceed freshness threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.days_since_collected > self._freshness_threshold:
                results.append(
                    {
                        "evidence_id": r.evidence_id,
                        "control_id": r.control_id,
                        "framework": r.framework,
                        "evidence_method": r.evidence_method.value,
                        "days_since_collected": r.days_since_collected,
                        "evidence_freshness": r.evidence_freshness.value,
                    }
                )
        results.sort(key=lambda x: x["days_since_collected"], reverse=True)
        return results

    def analyze_collection_automation(self) -> list[dict[str, Any]]:
        """Analyze evidence collection automation rates by framework."""
        fw_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            fw = r.framework or "unspecified"
            fw_data.setdefault(fw, {"total": 0, "automated": 0, "manual": 0})
            fw_data[fw]["total"] += 1
            if r.evidence_method in (EvidenceMethod.AUTOMATED, EvidenceMethod.API_PULL):
                fw_data[fw]["automated"] += 1
            if r.evidence_method == EvidenceMethod.MANUAL:
                fw_data[fw]["manual"] += 1
        results: list[dict[str, Any]] = []
        for fw, data in fw_data.items():
            auto_pct = (
                round(data["automated"] / data["total"] * 100, 2) if data["total"] > 0 else 0.0
            )
            results.append(
                {
                    "framework": fw,
                    "total_evidence": data["total"],
                    "automated": data["automated"],
                    "manual": data["manual"],
                    "automation_pct": auto_pct,
                }
            )
        results.sort(key=lambda x: x["automation_pct"])
        return results

    def rank_controls_by_readiness(self) -> list[dict[str, Any]]:
        """Rank controls by audit readiness completeness."""
        ctrl_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            c = r.control_id
            ctrl_data.setdefault(c, {"total": 0, "ready": 0})
            ctrl_data[c]["total"] += 1
            if r.audit_readiness == AuditReadiness.READY:
                ctrl_data[c]["ready"] += 1
        results: list[dict[str, Any]] = []
        for ctrl, data in ctrl_data.items():
            pct = round(data["ready"] / data["total"] * 100, 2) if data["total"] > 0 else 0.0
            results.append(
                {
                    "control_id": ctrl,
                    "total_evidence": data["total"],
                    "ready": data["ready"],
                    "readiness_pct": pct,
                    "rank": 0,
                }
            )
        results.sort(key=lambda x: x["readiness_pct"])
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
