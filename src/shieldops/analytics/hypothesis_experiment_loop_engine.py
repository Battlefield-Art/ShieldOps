"""Hypothesis Experiment Loop Engine —
advance loop phases, evaluate evidence,
and select the next hypothesis to test."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class LoopPhase(StrEnum):
    HYPOTHESIS = "hypothesis"
    EXPERIMENT = "experiment"
    EVALUATE = "evaluate"
    ITERATE = "iterate"


class HypothesisStatus(StrEnum):
    PROPOSED = "proposed"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class ExperimentOutcome(StrEnum):
    IMPROVEMENT = "improvement"
    NO_CHANGE = "no_change"
    REGRESSION = "regression"
    INCONCLUSIVE = "inconclusive"


# --- Models ---


class HypothesisExperimentRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hypothesis_id: str = ""
    phase: LoopPhase = LoopPhase.HYPOTHESIS
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    outcome: ExperimentOutcome = ExperimentOutcome.INCONCLUSIVE
    confidence: float = 0.0
    improvement_delta: float = 0.0
    iterations: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class HypothesisExperimentAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hypothesis_id: str = ""
    next_phase: LoopPhase = LoopPhase.EXPERIMENT
    current_status: HypothesisStatus = HypothesisStatus.PROPOSED
    evidence_strength: float = 0.0
    should_continue: bool = True
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class HypothesisExperimentReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    by_phase: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    confirmed_hypotheses: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class HypothesisExperimentLoopEngine:
    """Advance loop phases, evaluate hypothesis evidence,
    and select next hypothesis to test."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[HypothesisExperimentRecord] = []
        self._analyses: dict[str, HypothesisExperimentAnalysis] = {}
        logger.info(
            "hypothesis_experiment_loop.init",
            max_records=max_records,
        )

    def add_record(
        self,
        hypothesis_id: str = "",
        phase: LoopPhase = LoopPhase.HYPOTHESIS,
        status: HypothesisStatus = HypothesisStatus.PROPOSED,
        outcome: ExperimentOutcome = ExperimentOutcome.INCONCLUSIVE,
        confidence: float = 0.0,
        improvement_delta: float = 0.0,
        iterations: int = 0,
        description: str = "",
    ) -> HypothesisExperimentRecord:
        record = HypothesisExperimentRecord(
            hypothesis_id=hypothesis_id,
            phase=phase,
            status=status,
            outcome=outcome,
            confidence=confidence,
            improvement_delta=improvement_delta,
            iterations=iterations,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "hypothesis_experiment.record_added",
            record_id=record.id,
            hypothesis_id=hypothesis_id,
        )
        return record

    def process(self, key: str) -> HypothesisExperimentAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        phase_order = [
            LoopPhase.HYPOTHESIS,
            LoopPhase.EXPERIMENT,
            LoopPhase.EVALUATE,
            LoopPhase.ITERATE,
        ]
        cur_idx = phase_order.index(rec.phase) if rec.phase in phase_order else 0
        next_phase = phase_order[min(cur_idx + 1, len(phase_order) - 1)]
        evidence = min(1.0, rec.confidence * (1.0 + rec.improvement_delta))
        should_continue = rec.status not in (
            HypothesisStatus.CONFIRMED,
            HypothesisStatus.REJECTED,
        )
        analysis = HypothesisExperimentAnalysis(
            hypothesis_id=rec.hypothesis_id,
            next_phase=next_phase,
            current_status=rec.status,
            evidence_strength=round(evidence, 4),
            should_continue=should_continue,
            description=f"Hypothesis {rec.hypothesis_id} -> {next_phase.value}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> HypothesisExperimentReport:
        by_p: dict[str, int] = {}
        by_s: dict[str, int] = {}
        by_o: dict[str, int] = {}
        confirmed: list[str] = []
        for r in self._records:
            by_p[r.phase.value] = by_p.get(r.phase.value, 0) + 1
            by_s[r.status.value] = by_s.get(r.status.value, 0) + 1
            by_o[r.outcome.value] = by_o.get(r.outcome.value, 0) + 1
            if r.status == HypothesisStatus.CONFIRMED and r.hypothesis_id not in confirmed:
                confirmed.append(r.hypothesis_id)
        recs: list[str] = []
        rejected = by_s.get("rejected", 0)
        if rejected > 0:
            recs.append(f"{rejected} hypotheses rejected — review experimental setup")
        inconcl = by_o.get("inconclusive", 0)
        if inconcl > 0:
            recs.append(f"{inconcl} inconclusive experiments — increase sample size")
        if not recs:
            recs.append("Hypothesis loop is progressing well")
        return HypothesisExperimentReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            by_phase=by_p,
            by_status=by_s,
            by_outcome=by_o,
            confirmed_hypotheses=confirmed[:10],
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        p_dist: dict[str, int] = {}
        for r in self._records:
            p_dist[r.phase.value] = p_dist.get(r.phase.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "phase_distribution": p_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("hypothesis_experiment_loop.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def advance_loop_phase(self, hypothesis_id: str) -> dict[str, Any]:
        """Advance the loop phase for a given hypothesis."""
        phase_order = [
            LoopPhase.HYPOTHESIS,
            LoopPhase.EXPERIMENT,
            LoopPhase.EVALUATE,
            LoopPhase.ITERATE,
        ]
        hyp_recs = [r for r in self._records if r.hypothesis_id == hypothesis_id]
        if not hyp_recs:
            return {"hypothesis_id": hypothesis_id, "error": "not_found"}
        latest = max(hyp_recs, key=lambda x: x.created_at)
        cur_idx = phase_order.index(latest.phase) if latest.phase in phase_order else 0
        next_phase = phase_order[min(cur_idx + 1, len(phase_order) - 1)]
        at_end = cur_idx == len(phase_order) - 1
        return {
            "hypothesis_id": hypothesis_id,
            "current_phase": latest.phase.value,
            "next_phase": next_phase.value,
            "at_final_phase": at_end,
            "iterations": latest.iterations,
        }

    def evaluate_hypothesis_evidence(self, hypothesis_id: str) -> dict[str, Any]:
        """Aggregate evidence strength for a hypothesis."""
        hyp_recs = [r for r in self._records if r.hypothesis_id == hypothesis_id]
        if not hyp_recs:
            return {"hypothesis_id": hypothesis_id, "evidence_strength": 0.0}
        improvements = [r for r in hyp_recs if r.outcome == ExperimentOutcome.IMPROVEMENT]
        regressions = [r for r in hyp_recs if r.outcome == ExperimentOutcome.REGRESSION]
        avg_conf = sum(r.confidence for r in hyp_recs) / len(hyp_recs)
        avg_delta = sum(r.improvement_delta for r in hyp_recs) / len(hyp_recs)
        support_ratio = len(improvements) / len(hyp_recs) if hyp_recs else 0.0
        evidence = round(avg_conf * support_ratio, 4)
        verdict = (
            "confirmed"
            if evidence >= 0.7
            else "rejected"
            if len(regressions) > len(improvements)
            else "inconclusive"
        )
        return {
            "hypothesis_id": hypothesis_id,
            "evidence_strength": evidence,
            "avg_confidence": round(avg_conf, 4),
            "avg_improvement_delta": round(avg_delta, 4),
            "support_ratio": round(support_ratio, 4),
            "verdict": verdict,
            "total_experiments": len(hyp_recs),
        }

    def select_next_hypothesis(self) -> dict[str, Any]:
        """Select the highest-value untested hypothesis."""
        hyp_scores: dict[str, dict[str, Any]] = {}
        for r in self._records:
            hid = r.hypothesis_id
            if hid not in hyp_scores:
                hyp_scores[hid] = {
                    "status": r.status,
                    "max_confidence": 0.0,
                    "max_delta": 0.0,
                    "iterations": 0,
                }
            hyp_scores[hid]["max_confidence"] = max(hyp_scores[hid]["max_confidence"], r.confidence)
            hyp_scores[hid]["max_delta"] = max(hyp_scores[hid]["max_delta"], r.improvement_delta)
            hyp_scores[hid]["iterations"] += 1
            hyp_scores[hid]["status"] = r.status
        candidates = [
            hid
            for hid, data in hyp_scores.items()
            if data["status"] in (HypothesisStatus.PROPOSED, HypothesisStatus.TESTING)
        ]
        if not candidates:
            return {"next_hypothesis": None, "reason": "no_candidates"}
        scored = sorted(
            candidates,
            key=lambda x: hyp_scores[x]["max_confidence"] + hyp_scores[x]["max_delta"],
            reverse=True,
        )
        best = scored[0]
        return {
            "next_hypothesis": best,
            "expected_confidence": hyp_scores[best]["max_confidence"],
            "expected_delta": hyp_scores[best]["max_delta"],
            "prior_iterations": hyp_scores[best]["iterations"],
        }
