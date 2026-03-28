"""Evidence Chain Engine — track forensic chain of custody."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CustodyAction(StrEnum):
    COLLECTED = "collected"
    TRANSFERRED = "transferred"
    ANALYZED = "analyzed"
    STORED = "stored"
    RELEASED = "released"


class EvidenceState(StrEnum):
    PRISTINE = "pristine"
    IN_ANALYSIS = "in_analysis"
    VERIFIED = "verified"
    COMPROMISED = "compromised"
    ARCHIVED = "archived"


class ForensicMethod(StrEnum):
    DISK_IMAGING = "disk_imaging"
    MEMORY_FORENSICS = "memory_forensics"
    NETWORK_CAPTURE = "network_capture"
    LOG_ANALYSIS = "log_analysis"
    MALWARE_ANALYSIS = "malware_analysis"


# --- Models ---


class CustodyRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_id: str = ""
    action: CustodyAction = CustodyAction.COLLECTED
    state: EvidenceState = EvidenceState.PRISTINE
    method: ForensicMethod = ForensicMethod.DISK_IMAGING
    handler: str = ""
    hash_before: str = ""
    hash_after: str = ""
    notes: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CustodyAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_id: str = ""
    action: CustodyAction = CustodyAction.COLLECTED
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CustodyReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    integrity_rate: float = 0.0
    by_action: dict[str, int] = Field(default_factory=dict)
    by_state: dict[str, int] = Field(default_factory=dict)
    by_method: dict[str, int] = Field(default_factory=dict)
    compromised_items: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class EvidenceChainEngine:
    """Track forensic evidence chain of custody."""

    def __init__(
        self,
        max_records: int = 200000,
        integrity_threshold: float = 95.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = integrity_threshold
        self._records: list[CustodyRecord] = []
        self._analyses: list[CustodyAnalysis] = []
        logger.info(
            "evidence_chain_engine.initialized",
            max_records=max_records,
        )

    # -- record / get / list ---

    def add_record(
        self,
        evidence_id: str,
        action: CustodyAction = (CustodyAction.COLLECTED),
        state: EvidenceState = EvidenceState.PRISTINE,
        method: ForensicMethod = (ForensicMethod.DISK_IMAGING),
        handler: str = "",
        hash_before: str = "",
        hash_after: str = "",
        notes: str = "",
        service: str = "",
        team: str = "",
    ) -> CustodyRecord:
        record = CustodyRecord(
            evidence_id=evidence_id,
            action=action,
            state=state,
            method=method,
            handler=handler,
            hash_before=hash_before,
            hash_after=hash_after,
            notes=notes,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "evidence_chain_engine.record_added",
            record_id=record.id,
            evidence_id=evidence_id,
            action=action.value,
        )
        return record

    def get_record(self, record_id: str) -> CustodyRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        action: CustodyAction | None = None,
        state: EvidenceState | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CustodyRecord]:
        results = list(self._records)
        if action is not None:
            results = [r for r in results if r.action == action]
        if state is not None:
            results = [r for r in results if r.state == state]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        evidence_id: str,
        action: CustodyAction = (CustodyAction.COLLECTED),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CustodyAnalysis:
        analysis = CustodyAnalysis(
            evidence_id=evidence_id,
            action=action,
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

    def log_custody_action(
        self,
    ) -> list[dict[str, Any]]:
        """Summarize custody actions by evidence."""
        ev_data: dict[str, list[CustodyRecord]] = {}
        for r in self._records:
            ev_data.setdefault(r.evidence_id, []).append(r)
        results: list[dict[str, Any]] = []
        for ev_id, records in ev_data.items():
            latest = max(records, key=lambda x: x.created_at)
            results.append(
                {
                    "evidence_id": ev_id,
                    "total_actions": len(records),
                    "current_state": latest.state.value,
                    "last_handler": latest.handler,
                }
            )
        return sorted(
            results,
            key=lambda x: x["total_actions"],
            reverse=True,
        )

    def verify_chain(
        self,
    ) -> list[dict[str, Any]]:
        """Verify chain integrity via hashes."""
        ev_data: dict[str, list[CustodyRecord]] = {}
        for r in self._records:
            ev_data.setdefault(r.evidence_id, []).append(r)
        results: list[dict[str, Any]] = []
        for ev_id, records in ev_data.items():
            sorted_recs = sorted(records, key=lambda x: x.created_at)
            breaks = 0
            for i in range(1, len(sorted_recs)):
                prev = sorted_recs[i - 1]
                curr = sorted_recs[i]
                if prev.hash_after and curr.hash_before and prev.hash_after != curr.hash_before:
                    breaks += 1
            compromised = any(r.state == EvidenceState.COMPROMISED for r in records)
            results.append(
                {
                    "evidence_id": ev_id,
                    "chain_length": len(records),
                    "hash_breaks": breaks,
                    "compromised": compromised,
                    "integrity": "intact" if breaks == 0 and not compromised else "broken",
                }
            )
        return sorted(
            results,
            key=lambda x: x["hash_breaks"],
            reverse=True,
        )

    def generate_custody_report(
        self,
    ) -> list[dict[str, Any]]:
        """Generate per-method custody summary."""
        method_data: dict[str, list[CustodyRecord]] = {}
        for r in self._records:
            method_data.setdefault(r.method.value, []).append(r)
        results: list[dict[str, Any]] = []
        for method, records in method_data.items():
            verified = sum(1 for r in records if r.state == EvidenceState.VERIFIED)
            rate = round(verified / len(records) * 100, 2) if records else 0.0
            results.append(
                {
                    "method": method,
                    "count": len(records),
                    "verified": verified,
                    "verification_rate": rate,
                }
            )
        return sorted(
            results,
            key=lambda x: x["verification_rate"],
        )

    # -- standard methods ---

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.evidence_id == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
        }

    def generate_report(self) -> CustodyReport:
        by_action: dict[str, int] = {}
        by_state: dict[str, int] = {}
        by_method: dict[str, int] = {}
        for r in self._records:
            by_action[r.action.value] = by_action.get(r.action.value, 0) + 1
            by_state[r.state.value] = by_state.get(r.state.value, 0) + 1
            by_method[r.method.value] = by_method.get(r.method.value, 0) + 1
        compromised = [r.evidence_id for r in self._records if r.state == EvidenceState.COMPROMISED]
        total = len(self._records)
        ok = total - len(compromised)
        rate = round(ok / total * 100, 2) if total else 100.0
        recs: list[str] = []
        if compromised:
            recs.append(f"{len(compromised)} compromised")
        if rate < self._threshold:
            recs.append(f"Integrity {rate}% below {self._threshold}%")
        if not recs:
            recs.append("Evidence Chain Engine is healthy")
        return CustodyReport(
            total_records=total,
            total_analyses=len(self._analyses),
            integrity_rate=rate,
            by_action=by_action,
            by_state=by_state,
            by_method=by_method,
            compromised_items=list(set(compromised)),
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("evidence_chain_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        action_dist: dict[str, int] = {}
        for r in self._records:
            k = r.action.value
            action_dist[k] = action_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "integrity_threshold": self._threshold,
            "action_distribution": action_dist,
            "unique_evidence": len({r.evidence_id for r in self._records}),
            "unique_handlers": len({r.handler for r in self._records}),
        }
