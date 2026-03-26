"""MDR Investigation Engine — track agentic MDR workflows."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class InvestigationPhase(StrEnum):
    DETECTION = "detection"
    TRIAGE = "triage"
    ANALYSIS = "analysis"
    CONTAINMENT = "containment"
    REMEDIATION = "remediation"


class VendorSource(StrEnum):
    CROWDSTRIKE = "crowdstrike"
    DEFENDER = "defender"
    WIZ = "wiz"
    SHIELDOPS = "shieldops"
    CUSTOM = "custom"


class InvestigationOutcome(StrEnum):
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    FALSE_POSITIVE = "false_positive"
    PENDING = "pending"
    TIMEOUT = "timeout"


# --- Models ---


class InvestigationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str = ""
    phase: InvestigationPhase = InvestigationPhase.DETECTION
    vendor: VendorSource = VendorSource.SHIELDOPS
    outcome: InvestigationOutcome = InvestigationOutcome.PENDING
    duration_seconds: float = 0.0
    automated: bool = False
    analyst: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class InvestigationAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    investigation_id: str = ""
    phase: InvestigationPhase = InvestigationPhase.DETECTION
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class InvestigationReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_duration: float = 0.0
    closure_rate: float = 0.0
    automation_rate: float = 0.0
    by_phase: dict[str, int] = Field(default_factory=dict)
    by_vendor: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class MdrInvestigationEngine:
    """Track agentic MDR investigation workflows."""

    def __init__(
        self,
        max_records: int = 200000,
        closure_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._closure_threshold = closure_threshold
        self._records: list[InvestigationRecord] = []
        self._analyses: list[InvestigationAnalysis] = []
        logger.info(
            "mdr_investigation_engine.initialized",
            max_records=max_records,
        )

    # -- record --

    def add_record(
        self,
        investigation_id: str = "",
        phase: InvestigationPhase = (InvestigationPhase.DETECTION),
        vendor: VendorSource = VendorSource.SHIELDOPS,
        outcome: InvestigationOutcome = (InvestigationOutcome.PENDING),
        duration_seconds: float = 0.0,
        automated: bool = False,
        analyst: str = "",
        service: str = "",
        team: str = "",
    ) -> InvestigationRecord:
        record = InvestigationRecord(
            investigation_id=investigation_id,
            phase=phase,
            vendor=vendor,
            outcome=outcome,
            duration_seconds=duration_seconds,
            automated=automated,
            analyst=analyst,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "mdr_investigation_engine.record_added",
            record_id=record.id,
            investigation_id=investigation_id,
        )
        return record

    # -- process --

    def process(self, investigation_id: str) -> InvestigationAnalysis:
        relevant = [r for r in self._records if r.investigation_id == investigation_id]
        if not relevant:
            analysis = InvestigationAnalysis(
                investigation_id=investigation_id,
                description="no records found",
            )
            self._analyses.append(analysis)
            return analysis
        durations = [r.duration_seconds for r in relevant]
        avg_dur = sum(durations) / len(durations)
        resolved = sum(1 for r in relevant if r.outcome == InvestigationOutcome.RESOLVED)
        rate = (resolved / len(relevant)) * 100
        breached = rate < self._closure_threshold
        analysis = InvestigationAnalysis(
            investigation_id=investigation_id,
            analysis_score=round(rate, 2),
            threshold=self._closure_threshold,
            breached=breached,
            description=(f"avg_duration={round(avg_dur, 2)}s closure_rate={round(rate, 2)}%"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain methods --

    def track_investigation_time(
        self,
    ) -> dict[str, Any]:
        """Avg duration by phase."""
        phase_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.phase.value
            phase_data.setdefault(key, []).append(r.duration_seconds)
        result: dict[str, Any] = {}
        for phase, durs in phase_data.items():
            result[phase] = {
                "count": len(durs),
                "avg_duration": round(sum(durs) / len(durs), 2),
            }
        return result

    def calculate_closure_rate(
        self,
    ) -> dict[str, Any]:
        """Closure rate by vendor."""
        vendor_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.vendor.value
            vendor_data.setdefault(key, {"total": 0, "resolved": 0})
            vendor_data[key]["total"] += 1
            if r.outcome == InvestigationOutcome.RESOLVED:
                vendor_data[key]["resolved"] += 1
        result: dict[str, Any] = {}
        for vendor, data in vendor_data.items():
            rate = 0.0
            if data["total"] > 0:
                rate = data["resolved"] / data["total"] * 100
            result[vendor] = {
                "total": data["total"],
                "resolved": data["resolved"],
                "closure_rate": round(rate, 2),
            }
        return result

    def identify_automation_gaps(
        self,
    ) -> list[dict[str, Any]]:
        """Find phases with low automation."""
        phase_auto: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.phase.value
            phase_auto.setdefault(
                key,
                {"total": 0, "automated": 0},
            )
            phase_auto[key]["total"] += 1
            if r.automated:
                phase_auto[key]["automated"] += 1
        gaps: list[dict[str, Any]] = []
        for phase, data in phase_auto.items():
            rate = 0.0
            if data["total"] > 0:
                rate = data["automated"] / data["total"] * 100
            if rate < 50.0:
                gaps.append(
                    {
                        "phase": phase,
                        "automation_rate": round(rate, 2),
                        "total": data["total"],
                        "gap": "low_automation",
                    }
                )
        return sorted(
            gaps,
            key=lambda x: x["automation_rate"],
        )

    # -- report / stats --

    def generate_report(self) -> InvestigationReport:
        by_phase: dict[str, int] = {}
        by_vendor: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        for r in self._records:
            by_phase[r.phase.value] = by_phase.get(r.phase.value, 0) + 1
            by_vendor[r.vendor.value] = by_vendor.get(r.vendor.value, 0) + 1
            by_outcome[r.outcome.value] = by_outcome.get(r.outcome.value, 0) + 1
        durations = [r.duration_seconds for r in self._records]
        avg_dur = round(sum(durations) / len(durations), 2) if durations else 0.0
        resolved = sum(1 for r in self._records if r.outcome == InvestigationOutcome.RESOLVED)
        closure = (
            round(
                resolved / len(self._records) * 100,
                2,
            )
            if self._records
            else 0.0
        )
        auto_count = sum(1 for r in self._records if r.automated)
        auto_rate = (
            round(
                auto_count / len(self._records) * 100,
                2,
            )
            if self._records
            else 0.0
        )
        recs: list[str] = []
        if closure < self._closure_threshold:
            recs.append(f"Closure rate {closure}% below threshold {self._closure_threshold}%")
        if auto_rate < 50.0:
            recs.append(f"Automation rate {auto_rate}% is below 50%")
        if not recs:
            recs.append("MDR investigation performance is healthy")
        return InvestigationReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_duration=avg_dur,
            closure_rate=closure,
            automation_rate=auto_rate,
            by_phase=by_phase,
            by_vendor=by_vendor,
            by_outcome=by_outcome,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "closure_threshold": (self._closure_threshold),
            "unique_investigations": len({r.investigation_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("mdr_investigation_engine.cleared")
        return {"status": "cleared"}
