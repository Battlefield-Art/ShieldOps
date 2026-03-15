"""Risk Notable Generator Engine —
evaluate notable fidelity, detect threshold drift,
rank notables by urgency."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class NotableTrigger(StrEnum):
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    SPIKE_DETECTED = "spike_detected"
    PATTERN_MATCH = "pattern_match"
    ANOMALY_CORRELATION = "anomaly_correlation"


class NotablePriority(StrEnum):
    P1_IMMEDIATE = "p1_immediate"
    P2_HIGH = "p2_high"
    P3_MEDIUM = "p3_medium"
    P4_LOW = "p4_low"


class NotableDisposition(StrEnum):
    TRUE_POSITIVE = "true_positive"
    BENIGN = "benign"
    NEEDS_INVESTIGATION = "needs_investigation"
    SUPPRESSED = "suppressed"


# --- Models ---


class RiskNotableRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    notable_id: str = ""
    entity_id: str = ""
    trigger: NotableTrigger = NotableTrigger.THRESHOLD_EXCEEDED
    priority: NotablePriority = NotablePriority.P4_LOW
    disposition: NotableDisposition = NotableDisposition.NEEDS_INVESTIGATION
    risk_score: float = 0.0
    threshold_value: float = 0.0
    fidelity_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskNotableAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    notable_id: str = ""
    trigger: NotableTrigger = NotableTrigger.THRESHOLD_EXCEEDED
    fidelity_rating: str = ""
    urgency_rank: int = 0
    threshold_drift_detected: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RiskNotableReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_risk_score: float = 0.0
    by_trigger: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    by_disposition: dict[str, int] = Field(default_factory=dict)
    top_urgent_notables: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class RiskNotableGeneratorEngine:
    """Evaluate notable fidelity, detect threshold drift,
    rank notables by urgency."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[RiskNotableRecord] = []
        self._analyses: dict[str, RiskNotableAnalysis] = {}
        logger.info("risk_notable_generator_engine.init", max_records=max_records)

    def add_record(
        self,
        notable_id: str = "",
        entity_id: str = "",
        trigger: NotableTrigger = NotableTrigger.THRESHOLD_EXCEEDED,
        priority: NotablePriority = NotablePriority.P4_LOW,
        disposition: NotableDisposition = NotableDisposition.NEEDS_INVESTIGATION,
        risk_score: float = 0.0,
        threshold_value: float = 0.0,
        fidelity_score: float = 0.0,
        description: str = "",
    ) -> RiskNotableRecord:
        record = RiskNotableRecord(
            notable_id=notable_id,
            entity_id=entity_id,
            trigger=trigger,
            priority=priority,
            disposition=disposition,
            risk_score=risk_score,
            threshold_value=threshold_value,
            fidelity_score=fidelity_score,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "risk_notable.record_added",
            record_id=record.id,
            notable_id=notable_id,
        )
        return record

    def process(self, key: str) -> RiskNotableAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        fidelity_rating = (
            "high"
            if rec.fidelity_score >= 0.8
            else "medium"
            if rec.fidelity_score >= 0.5
            else "low"
        )
        priority_urgency = {
            NotablePriority.P1_IMMEDIATE: 4,
            NotablePriority.P2_HIGH: 3,
            NotablePriority.P3_MEDIUM: 2,
            NotablePriority.P4_LOW: 1,
        }
        urgency = priority_urgency.get(rec.priority, 1)
        drift = rec.risk_score > rec.threshold_value * 1.5
        analysis = RiskNotableAnalysis(
            notable_id=rec.notable_id,
            trigger=rec.trigger,
            fidelity_rating=fidelity_rating,
            urgency_rank=urgency,
            threshold_drift_detected=drift,
            description=f"Notable {rec.notable_id} fidelity={fidelity_rating}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> RiskNotableReport:
        by_tr: dict[str, int] = {}
        by_pr: dict[str, int] = {}
        by_di: dict[str, int] = {}
        scores: list[float] = []
        for r in self._records:
            by_tr[r.trigger.value] = by_tr.get(r.trigger.value, 0) + 1
            by_pr[r.priority.value] = by_pr.get(r.priority.value, 0) + 1
            by_di[r.disposition.value] = by_di.get(r.disposition.value, 0) + 1
            scores.append(r.risk_score)
        avg_s = round(sum(scores) / len(scores), 4) if scores else 0.0
        urgent = [
            r.notable_id
            for r in self._records
            if r.priority == NotablePriority.P1_IMMEDIATE and r.notable_id
        ][:10]
        recs: list[str] = []
        if urgent:
            recs.append(f"{len(urgent)} P1 immediate notables require attention")
        if not recs:
            recs.append("No critical notables detected")
        return RiskNotableReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_risk_score=avg_s,
            by_trigger=by_tr,
            by_priority=by_pr,
            by_disposition=by_di,
            top_urgent_notables=urgent,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        tr_dist: dict[str, int] = {}
        for r in self._records:
            tr_dist[r.trigger.value] = tr_dist.get(r.trigger.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "trigger_distribution": tr_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("risk_notable_generator_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def evaluate_notable_fidelity(self) -> list[dict[str, Any]]:
        """Evaluate fidelity of notables by disposition accuracy."""
        notable_data: dict[str, list[RiskNotableRecord]] = {}
        for r in self._records:
            notable_data.setdefault(r.notable_id, []).append(r)
        results: list[dict[str, Any]] = []
        for nid, recs in notable_data.items():
            tp_count = sum(1 for r in recs if r.disposition == NotableDisposition.TRUE_POSITIVE)
            total = len(recs)
            fidelity = round(tp_count / total, 4) if total else 0.0
            avg_fid = round(sum(r.fidelity_score for r in recs) / total, 4) if total else 0.0
            results.append(
                {
                    "notable_id": nid,
                    "total_occurrences": total,
                    "true_positive_count": tp_count,
                    "disposition_fidelity": fidelity,
                    "avg_fidelity_score": avg_fid,
                }
            )
        results.sort(key=lambda x: x["disposition_fidelity"], reverse=True)
        return results

    def detect_threshold_drift(self, drift_multiplier: float = 1.5) -> list[dict[str, Any]]:
        """Detect notables where risk scores have drifted far above threshold."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.threshold_value > 0:
                ratio = round(r.risk_score / r.threshold_value, 4)
                if ratio > drift_multiplier:
                    results.append(
                        {
                            "notable_id": r.notable_id,
                            "risk_score": r.risk_score,
                            "threshold_value": r.threshold_value,
                            "drift_ratio": ratio,
                            "trigger": r.trigger.value,
                        }
                    )
        results.sort(key=lambda x: x["drift_ratio"], reverse=True)
        return results

    def rank_notables_by_urgency(self) -> list[dict[str, Any]]:
        """Rank notables by combined urgency of priority and risk score."""
        priority_weights = {
            NotablePriority.P1_IMMEDIATE: 4,
            NotablePriority.P2_HIGH: 3,
            NotablePriority.P3_MEDIUM: 2,
            NotablePriority.P4_LOW: 1,
        }
        notable_urgency: dict[str, dict[str, Any]] = {}
        for r in self._records:
            pw = priority_weights.get(r.priority, 1)
            urgency_score = pw * r.risk_score
            if r.notable_id not in notable_urgency:
                notable_urgency[r.notable_id] = {
                    "notable_id": r.notable_id,
                    "urgency_score": urgency_score,
                    "priority": r.priority.value,
                    "risk_score": r.risk_score,
                    "trigger": r.trigger.value,
                }
            elif urgency_score > notable_urgency[r.notable_id]["urgency_score"]:
                notable_urgency[r.notable_id]["urgency_score"] = urgency_score
                notable_urgency[r.notable_id]["priority"] = r.priority.value
        results = list(notable_urgency.values())
        results.sort(key=lambda x: x["urgency_score"], reverse=True)
        for idx, entry in enumerate(results, 1):
            entry["rank"] = idx
        return results
