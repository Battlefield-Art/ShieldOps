"""Fault Injection Safety Engine — track fault injection safety and blast radius."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class SafetyGate(StrEnum):
    PRE_CHECK = "pre_check"
    CANARY = "canary"
    ROLLBACK_READY = "rollback_ready"
    SLO_GUARD = "slo_guard"
    BLAST_RADIUS = "blast_radius"


class GateOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    BYPASSED = "bypassed"
    TIMEOUT = "timeout"
    NOT_APPLICABLE = "not_applicable"


class RollbackReason(StrEnum):
    SLO_BREACH = "slo_breach"
    TIMEOUT = "timeout"
    MANUAL = "manual"
    CASCADING_FAILURE = "cascading_failure"
    SAFETY_GATE = "safety_gate"


# --- Models ---


class FaultInjectionSafetyRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    service_id: str = ""
    safety_gate: SafetyGate = SafetyGate.PRE_CHECK
    gate_outcome: GateOutcome = GateOutcome.PASSED
    rollback_reason: RollbackReason | None = None
    blast_radius_actual: int = 0
    blast_radius_limit: int = 0
    slo_impact_pct: float = 0.0
    rollback_triggered: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class FaultInjectionSafetyAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    experiment_id: str = ""
    analysis_score: float = 0.0
    safety_gate: SafetyGate = SafetyGate.PRE_CHECK
    all_gates_passed: bool = True
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class FaultInjectionSafetyReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    safety_pass_rate: float = 0.0
    by_gate: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    by_rollback_reason: dict[str, int] = Field(default_factory=dict)
    rollback_count: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class FaultInjectionSafetyEngine:
    """Track fault injection safety gates and blast radius compliance."""

    def __init__(
        self,
        max_records: int = 200000,
        safety_threshold: float = 95.0,
    ) -> None:
        self._max_records = max_records
        self._safety_threshold = safety_threshold
        self._records: list[FaultInjectionSafetyRecord] = []
        self._analyses: dict[str, FaultInjectionSafetyAnalysis] = {}
        logger.info(
            "fault_injection_safety_engine.init",
            max_records=max_records,
            safety_threshold=safety_threshold,
        )

    def add_record(
        self,
        experiment_id: str = "",
        service_id: str = "",
        safety_gate: SafetyGate = SafetyGate.PRE_CHECK,
        gate_outcome: GateOutcome = GateOutcome.PASSED,
        rollback_reason: RollbackReason | None = None,
        blast_radius_actual: int = 0,
        blast_radius_limit: int = 0,
        slo_impact_pct: float = 0.0,
        rollback_triggered: bool = False,
        description: str = "",
    ) -> FaultInjectionSafetyRecord:
        record = FaultInjectionSafetyRecord(
            experiment_id=experiment_id,
            service_id=service_id,
            safety_gate=safety_gate,
            gate_outcome=gate_outcome,
            rollback_reason=rollback_reason,
            blast_radius_actual=blast_radius_actual,
            blast_radius_limit=blast_radius_limit,
            slo_impact_pct=slo_impact_pct,
            rollback_triggered=rollback_triggered,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "fault_injection_safety_engine.record_added",
            record_id=record.id,
            experiment_id=experiment_id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> FaultInjectionSafetyAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        exp_recs = [r for r in self._records if r.experiment_id == rec.experiment_id]
        all_passed = all(r.gate_outcome == GateOutcome.PASSED for r in exp_recs)
        passed = sum(1 for r in exp_recs if r.gate_outcome == GateOutcome.PASSED)
        score = round(passed / len(exp_recs) * 100, 2) if exp_recs else 0.0
        analysis = FaultInjectionSafetyAnalysis(
            experiment_id=rec.experiment_id,
            analysis_score=score,
            safety_gate=rec.safety_gate,
            all_gates_passed=all_passed,
            data_points=len(exp_recs),
            description=(f"Safety score {score}% for experiment {rec.experiment_id}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> FaultInjectionSafetyReport:
        by_g: dict[str, int] = {}
        by_o: dict[str, int] = {}
        by_rr: dict[str, int] = {}
        passed = 0
        rollback_count = 0
        for r in self._records:
            by_g[r.safety_gate.value] = by_g.get(r.safety_gate.value, 0) + 1
            by_o[r.gate_outcome.value] = by_o.get(r.gate_outcome.value, 0) + 1
            if r.rollback_reason is not None:
                by_rr[r.rollback_reason.value] = by_rr.get(r.rollback_reason.value, 0) + 1
            if r.gate_outcome == GateOutcome.PASSED:
                passed += 1
            if r.rollback_triggered:
                rollback_count += 1
        total = len(self._records)
        pass_rate = round(passed / total * 100, 2) if total else 0.0
        recs: list[str] = []
        if pass_rate < self._safety_threshold:
            recs.append(f"Safety pass rate {pass_rate}% below threshold {self._safety_threshold}%")
        bypassed = by_o.get(GateOutcome.BYPASSED.value, 0)
        if bypassed:
            recs.append(f"{bypassed} safety gates bypassed — review process")
        if rollback_count:
            recs.append(f"{rollback_count} rollbacks triggered — analyze root causes")
        if not recs:
            recs.append("Fault injection safety healthy — all gates passing")
        return FaultInjectionSafetyReport(
            total_records=total,
            total_analyses=len(self._analyses),
            safety_pass_rate=pass_rate,
            by_gate=by_g,
            by_outcome=by_o,
            by_rollback_reason=by_rr,
            rollback_count=rollback_count,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        gate_dist: dict[str, int] = {}
        for r in self._records:
            k = r.safety_gate.value
            gate_dist[k] = gate_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "safety_threshold": self._safety_threshold,
            "gate_distribution": gate_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("fault_injection_safety_engine.cleared")
        return {"status": "cleared"}

    # -- domain methods ---

    def analyze_gate_failure_patterns(self) -> list[dict[str, Any]]:
        """Analyze which safety gates fail most often."""
        gate_pass: dict[str, int] = {}
        gate_fail: dict[str, int] = {}
        for r in self._records:
            k = r.safety_gate.value
            if r.gate_outcome == GateOutcome.PASSED:
                gate_pass[k] = gate_pass.get(k, 0) + 1
            elif r.gate_outcome == GateOutcome.FAILED:
                gate_fail[k] = gate_fail.get(k, 0) + 1
        results: list[dict[str, Any]] = []
        all_gates = set(gate_pass.keys()) | set(gate_fail.keys())
        for gate in all_gates:
            p = gate_pass.get(gate, 0)
            f = gate_fail.get(gate, 0)
            total = p + f
            fail_rate = round(f / total * 100, 2) if total > 0 else 0.0
            results.append(
                {
                    "safety_gate": gate,
                    "pass_count": p,
                    "fail_count": f,
                    "fail_rate_pct": fail_rate,
                }
            )
        results.sort(key=lambda x: x["fail_rate_pct"], reverse=True)
        return results

    def detect_blast_radius_breaches(self) -> list[dict[str, Any]]:
        """Detect experiments that exceeded blast radius limits."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.blast_radius_limit > 0 and r.blast_radius_actual > r.blast_radius_limit:
                results.append(
                    {
                        "experiment_id": r.experiment_id,
                        "service_id": r.service_id,
                        "actual": r.blast_radius_actual,
                        "limit": r.blast_radius_limit,
                        "overshoot": (r.blast_radius_actual - r.blast_radius_limit),
                    }
                )
        results.sort(key=lambda x: x["overshoot"], reverse=True)
        return results

    def summarize_rollback_causes(self) -> list[dict[str, Any]]:
        """Summarize rollback triggers by reason."""
        reason_counts: dict[str, int] = {}
        for r in self._records:
            if r.rollback_triggered and r.rollback_reason is not None:
                k = r.rollback_reason.value
                reason_counts[k] = reason_counts.get(k, 0) + 1
        results: list[dict[str, Any]] = []
        for reason, count in reason_counts.items():
            results.append({"rollback_reason": reason, "count": count})
        results.sort(key=lambda x: x["count"], reverse=True)
        return results
