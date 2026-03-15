"""Tactic Chain Risk Engine —
detect MITRE tactic chains, compute chain amplification,
predict chain completion."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ChainPattern(StrEnum):
    LINEAR_PROGRESSION = "linear_progression"
    BRANCHING = "branching"
    LOOPING = "looping"
    INCOMPLETE = "incomplete"


class ChainCompleteness(StrEnum):
    FULL_KILL_CHAIN = "full_kill_chain"
    PARTIAL_CHAIN = "partial_chain"
    SINGLE_TACTIC = "single_tactic"
    FRAGMENTED = "fragmented"


class AmplificationLevel(StrEnum):
    CRITICAL_AMPLIFY = "critical_amplify"
    HIGH_AMPLIFY = "high_amplify"
    MODERATE_AMPLIFY = "moderate_amplify"
    NO_AMPLIFY = "no_amplify"


# --- Models ---


class TacticChainRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    chain_id: str = ""
    entity_id: str = ""
    chain_pattern: ChainPattern = ChainPattern.INCOMPLETE
    chain_completeness: ChainCompleteness = ChainCompleteness.SINGLE_TACTIC
    amplification_level: AmplificationLevel = AmplificationLevel.NO_AMPLIFY
    tactic_sequence: list[str] = Field(default_factory=list)
    base_risk_score: float = 0.0
    amplified_risk_score: float = 0.0
    tactic_count: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TacticChainAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    chain_id: str = ""
    chain_pattern: ChainPattern = ChainPattern.INCOMPLETE
    amplification_factor: float = 0.0
    predicted_next_tactic: str = ""
    completion_probability: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TacticChainReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_amplified_risk: float = 0.0
    by_chain_pattern: dict[str, int] = Field(default_factory=dict)
    by_chain_completeness: dict[str, int] = Field(default_factory=dict)
    by_amplification_level: dict[str, int] = Field(default_factory=dict)
    critical_chain_ids: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class TacticChainRiskEngine:
    """Detect MITRE tactic chains, compute chain amplification,
    predict chain completion."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[TacticChainRecord] = []
        self._analyses: dict[str, TacticChainAnalysis] = {}
        logger.info("tactic_chain_risk_engine.init", max_records=max_records)

    def add_record(
        self,
        chain_id: str = "",
        entity_id: str = "",
        chain_pattern: ChainPattern = ChainPattern.INCOMPLETE,
        chain_completeness: ChainCompleteness = ChainCompleteness.SINGLE_TACTIC,
        amplification_level: AmplificationLevel = AmplificationLevel.NO_AMPLIFY,
        tactic_sequence: list[str] | None = None,
        base_risk_score: float = 0.0,
        amplified_risk_score: float = 0.0,
        tactic_count: int = 0,
        description: str = "",
    ) -> TacticChainRecord:
        record = TacticChainRecord(
            chain_id=chain_id,
            entity_id=entity_id,
            chain_pattern=chain_pattern,
            chain_completeness=chain_completeness,
            amplification_level=amplification_level,
            tactic_sequence=tactic_sequence or [],
            base_risk_score=base_risk_score,
            amplified_risk_score=amplified_risk_score,
            tactic_count=tactic_count,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "tactic_chain.record_added",
            record_id=record.id,
            chain_id=chain_id,
        )
        return record

    def process(self, key: str) -> TacticChainAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        amp_factors = {
            AmplificationLevel.CRITICAL_AMPLIFY: 3.0,
            AmplificationLevel.HIGH_AMPLIFY: 2.0,
            AmplificationLevel.MODERATE_AMPLIFY: 1.5,
            AmplificationLevel.NO_AMPLIFY: 1.0,
        }
        amp = amp_factors.get(rec.amplification_level, 1.0)
        completeness_prob = {
            ChainCompleteness.FULL_KILL_CHAIN: 1.0,
            ChainCompleteness.PARTIAL_CHAIN: 0.65,
            ChainCompleteness.SINGLE_TACTIC: 0.2,
            ChainCompleteness.FRAGMENTED: 0.35,
        }
        completion_prob = completeness_prob.get(rec.chain_completeness, 0.2)
        next_tactic = rec.tactic_sequence[-1] if rec.tactic_sequence else ""
        analysis = TacticChainAnalysis(
            chain_id=rec.chain_id,
            chain_pattern=rec.chain_pattern,
            amplification_factor=amp,
            predicted_next_tactic=next_tactic,
            completion_probability=completion_prob,
            description=f"Chain {rec.chain_id} amp={amp} completion={completion_prob}",
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> TacticChainReport:
        by_cp: dict[str, int] = {}
        by_cc: dict[str, int] = {}
        by_al: dict[str, int] = {}
        risks: list[float] = []
        for r in self._records:
            by_cp[r.chain_pattern.value] = by_cp.get(r.chain_pattern.value, 0) + 1
            by_cc[r.chain_completeness.value] = by_cc.get(r.chain_completeness.value, 0) + 1
            by_al[r.amplification_level.value] = by_al.get(r.amplification_level.value, 0) + 1
            risks.append(r.amplified_risk_score)
        avg_r = round(sum(risks) / len(risks), 4) if risks else 0.0
        crit = list(
            {
                r.chain_id
                for r in self._records
                if r.amplification_level == AmplificationLevel.CRITICAL_AMPLIFY and r.chain_id
            }
        )[:10]
        recs: list[str] = []
        if crit:
            recs.append(f"{len(crit)} tactic chains at critical amplification level")
        if not recs:
            recs.append("No critical tactic chain amplification detected")
        return TacticChainReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_amplified_risk=avg_r,
            by_chain_pattern=by_cp,
            by_chain_completeness=by_cc,
            by_amplification_level=by_al,
            critical_chain_ids=crit,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        al_dist: dict[str, int] = {}
        for r in self._records:
            al_dist[r.amplification_level.value] = al_dist.get(r.amplification_level.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "amplification_distribution": al_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("tactic_chain_risk_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def detect_tactic_chains(self, min_tactic_count: int = 2) -> list[dict[str, Any]]:
        """Detect multi-tactic chains with minimum sequence length."""
        chain_latest: dict[str, TacticChainRecord] = {}
        for r in self._records:
            chain_latest[r.chain_id] = r
        results: list[dict[str, Any]] = []
        for cid, rec in chain_latest.items():
            if rec.tactic_count >= min_tactic_count:
                results.append(
                    {
                        "chain_id": cid,
                        "entity_id": rec.entity_id,
                        "tactic_count": rec.tactic_count,
                        "chain_pattern": rec.chain_pattern.value,
                        "chain_completeness": rec.chain_completeness.value,
                        "tactic_sequence": rec.tactic_sequence,
                        "base_risk_score": rec.base_risk_score,
                    }
                )
        results.sort(key=lambda x: x["tactic_count"], reverse=True)
        return results

    def compute_chain_amplification(self) -> list[dict[str, Any]]:
        """Compute actual amplification factor for each chain."""
        amp_weights = {
            AmplificationLevel.CRITICAL_AMPLIFY: 3.0,
            AmplificationLevel.HIGH_AMPLIFY: 2.0,
            AmplificationLevel.MODERATE_AMPLIFY: 1.5,
            AmplificationLevel.NO_AMPLIFY: 1.0,
        }
        chain_latest: dict[str, TacticChainRecord] = {}
        for r in self._records:
            chain_latest[r.chain_id] = r
        results: list[dict[str, Any]] = []
        for cid, rec in chain_latest.items():
            amp = amp_weights.get(rec.amplification_level, 1.0)
            effective_amp = (
                round(rec.amplified_risk_score / rec.base_risk_score, 4)
                if rec.base_risk_score > 0
                else amp
            )
            results.append(
                {
                    "chain_id": cid,
                    "base_risk_score": rec.base_risk_score,
                    "amplified_risk_score": rec.amplified_risk_score,
                    "expected_amplification": amp,
                    "effective_amplification": effective_amp,
                    "amplification_level": rec.amplification_level.value,
                }
            )
        results.sort(key=lambda x: x["effective_amplification"], reverse=True)
        return results

    def predict_chain_completion(self) -> list[dict[str, Any]]:
        """Predict likelihood of kill chain completion per active chain."""
        completeness_prob = {
            ChainCompleteness.FULL_KILL_CHAIN: 1.0,
            ChainCompleteness.PARTIAL_CHAIN: 0.65,
            ChainCompleteness.SINGLE_TACTIC: 0.2,
            ChainCompleteness.FRAGMENTED: 0.35,
        }
        pattern_modifier = {
            ChainPattern.LINEAR_PROGRESSION: 1.2,
            ChainPattern.BRANCHING: 0.9,
            ChainPattern.LOOPING: 1.0,
            ChainPattern.INCOMPLETE: 0.6,
        }
        chain_latest: dict[str, TacticChainRecord] = {}
        for r in self._records:
            chain_latest[r.chain_id] = r
        results: list[dict[str, Any]] = []
        for cid, rec in chain_latest.items():
            base_prob = completeness_prob.get(rec.chain_completeness, 0.2)
            modifier = pattern_modifier.get(rec.chain_pattern, 1.0)
            completion_prob = round(min(base_prob * modifier, 1.0), 4)
            results.append(
                {
                    "chain_id": cid,
                    "entity_id": rec.entity_id,
                    "completion_probability": completion_prob,
                    "chain_pattern": rec.chain_pattern.value,
                    "chain_completeness": rec.chain_completeness.value,
                    "tactic_count": rec.tactic_count,
                    "high_risk": completion_prob >= 0.6,
                }
            )
        results.sort(key=lambda x: x["completion_probability"], reverse=True)
        return results
