"""SOC Evidence Chain — immutable audit trail linking automated decisions to evidence."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class EvidenceType(StrEnum):
    VENDOR_ALERT = "vendor_alert"
    CORRELATION_RESULT = "correlation_result"
    LLM_ANALYSIS = "llm_analysis"
    POLICY_EVALUATION = "policy_evaluation"
    HUMAN_DECISION = "human_decision"
    AUTOMATED_ACTION = "automated_action"


class DecisionOutcome(StrEnum):
    APPROVED = "approved"
    MODIFIED = "modified"
    REJECTED = "rejected"
    AUTO_EXECUTED = "auto_executed"
    ESCALATED = "escalated"


class ChainStatus(StrEnum):
    BUILDING = "building"
    COMPLETE = "complete"
    DISPUTED = "disputed"
    ARCHIVED = "archived"


# --- Models ---


class EvidenceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    situation_id: str = ""
    evidence_type: EvidenceType = EvidenceType.VENDOR_ALERT
    source_vendor: str = ""
    raw_data_ref: str = ""
    summary: str = ""
    confidence: float = 0.0
    timestamp: float = Field(default_factory=time.time)


class DecisionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    situation_id: str = ""
    action_proposed: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    llm_reasoning: str = ""
    confidence: float = 0.0
    outcome: DecisionOutcome = DecisionOutcome.APPROVED
    decided_by: str = ""
    decided_at: float = Field(default_factory=time.time)


class EvidenceChainReport(BaseModel):
    total_evidence: int = 0
    total_decisions: int = 0
    unique_situations: int = 0
    by_evidence_type: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    incomplete_chains: int = 0
    avg_evidence_per_decision: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class SOCEvidenceChain:
    """Immutable audit trail linking every automated decision to its evidence."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._evidence: list[EvidenceRecord] = []
        self._decisions: list[DecisionRecord] = []
        logger.info("soc_evidence_chain.initialized", max_records=max_records)

    # -- evidence management --------------------------------------------------

    def add_evidence(
        self,
        situation_id: str,
        evidence_type: EvidenceType = EvidenceType.VENDOR_ALERT,
        source_vendor: str = "",
        summary: str = "",
        confidence: float = 0.0,
        raw_data_ref: str = "",
    ) -> EvidenceRecord:
        record = EvidenceRecord(
            situation_id=situation_id,
            evidence_type=evidence_type,
            source_vendor=source_vendor,
            raw_data_ref=raw_data_ref,
            summary=summary,
            confidence=confidence,
        )
        self._evidence.append(record)
        if len(self._evidence) > self._max_records:
            self._evidence = self._evidence[-self._max_records :]
        logger.info(
            "soc_evidence_chain.evidence_added",
            record_id=record.id,
            situation_id=situation_id,
            evidence_type=evidence_type.value,
            source_vendor=source_vendor,
        )
        return record

    def record_decision(
        self,
        situation_id: str,
        action_proposed: str,
        evidence_ids: list[str] | None = None,
        llm_reasoning: str = "",
        confidence: float = 0.0,
        decided_by: str = "",
        outcome: DecisionOutcome = DecisionOutcome.APPROVED,
    ) -> DecisionRecord:
        record = DecisionRecord(
            situation_id=situation_id,
            action_proposed=action_proposed,
            evidence_ids=evidence_ids or [],
            llm_reasoning=llm_reasoning,
            confidence=confidence,
            decided_by=decided_by,
            outcome=outcome,
        )
        self._decisions.append(record)
        if len(self._decisions) > self._max_records:
            self._decisions = self._decisions[-self._max_records :]
        logger.info(
            "soc_evidence_chain.decision_recorded",
            decision_id=record.id,
            situation_id=situation_id,
            outcome=outcome.value,
            decided_by=decided_by,
        )
        return record

    def get_chain(self, situation_id: str) -> dict[str, Any]:
        """Return complete evidence chain for a situation."""
        evidence = [e for e in self._evidence if e.situation_id == situation_id]
        decisions = [d for d in self._decisions if d.situation_id == situation_id]
        evidence.sort(key=lambda e: e.timestamp)
        decisions.sort(key=lambda d: d.decided_at)
        return {
            "situation_id": situation_id,
            "evidence": [e.model_dump() for e in evidence],
            "decisions": [d.model_dump() for d in decisions],
            "evidence_count": len(evidence),
            "decision_count": len(decisions),
            "status": self._compute_chain_status(evidence, decisions),
        }

    def _compute_chain_status(
        self,
        evidence: list[EvidenceRecord],
        decisions: list[DecisionRecord],
    ) -> str:
        if not evidence and not decisions:
            return ChainStatus.BUILDING.value
        if any(d.outcome == DecisionOutcome.ESCALATED for d in decisions):
            return ChainStatus.DISPUTED.value
        if decisions and all(
            d.outcome in (DecisionOutcome.APPROVED, DecisionOutcome.AUTO_EXECUTED)
            for d in decisions
        ):
            return ChainStatus.COMPLETE.value
        return ChainStatus.BUILDING.value

    def validate_chain_completeness(self, situation_id: str) -> dict[str, Any]:
        """Check that all decisions have supporting evidence."""
        evidence_ids = {e.id for e in self._evidence if e.situation_id == situation_id}
        decisions = [d for d in self._decisions if d.situation_id == situation_id]
        unsupported: list[str] = []
        for d in decisions:
            if not d.evidence_ids or not all(eid in evidence_ids for eid in d.evidence_ids):
                unsupported.append(d.id)
        return {
            "situation_id": situation_id,
            "total_decisions": len(decisions),
            "unsupported_decisions": len(unsupported),
            "unsupported_ids": unsupported,
            "is_complete": len(unsupported) == 0 and len(decisions) > 0,
        }

    # -- domain operations ----------------------------------------------------

    def get_evidence_by_type(self, evidence_type: EvidenceType) -> list[EvidenceRecord]:
        """Return all evidence of a given type."""
        return [e for e in self._evidence if e.evidence_type == evidence_type]

    def get_decisions_by_outcome(self, outcome: DecisionOutcome) -> list[DecisionRecord]:
        """Return all decisions with a given outcome."""
        return [d for d in self._decisions if d.outcome == outcome]

    def compute_confidence_trend(self, situation_id: str) -> list[dict[str, Any]]:
        """Track confidence scores across evidence for a situation over time."""
        evidence = sorted(
            [e for e in self._evidence if e.situation_id == situation_id],
            key=lambda e: e.timestamp,
        )
        return [
            {"id": e.id, "confidence": e.confidence, "timestamp": e.timestamp} for e in evidence
        ]

    # -- report / stats -------------------------------------------------------

    def generate_chain_report(self) -> EvidenceChainReport:
        by_type: dict[str, int] = {}
        for e in self._evidence:
            by_type[e.evidence_type.value] = by_type.get(e.evidence_type.value, 0) + 1
        by_outcome: dict[str, int] = {}
        for d in self._decisions:
            by_outcome[d.outcome.value] = by_outcome.get(d.outcome.value, 0) + 1
        situations = {e.situation_id for e in self._evidence} | {
            d.situation_id for d in self._decisions
        }
        total_evidence_refs = sum(len(d.evidence_ids) for d in self._decisions)
        avg_evidence = (
            round(total_evidence_refs / len(self._decisions), 2) if self._decisions else 0.0
        )
        incomplete = 0
        for sid in situations:
            result = self.validate_chain_completeness(sid)
            if not result["is_complete"]:
                incomplete += 1
        recs: list[str] = []
        if incomplete > 0:
            recs.append(f"{incomplete} situation(s) have incomplete evidence chains")
        escalated = by_outcome.get(DecisionOutcome.ESCALATED.value, 0)
        if escalated > 0:
            recs.append(f"{escalated} decision(s) escalated — review required")
        if not recs:
            recs.append("All evidence chains are complete and valid")
        return EvidenceChainReport(
            total_evidence=len(self._evidence),
            total_decisions=len(self._decisions),
            unique_situations=len(situations),
            by_evidence_type=by_type,
            by_outcome=by_outcome,
            incomplete_chains=incomplete,
            avg_evidence_per_decision=avg_evidence,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        situations = {e.situation_id for e in self._evidence} | {
            d.situation_id for d in self._decisions
        }
        type_dist: dict[str, int] = {}
        for e in self._evidence:
            type_dist[e.evidence_type.value] = type_dist.get(e.evidence_type.value, 0) + 1
        return {
            "total_evidence": len(self._evidence),
            "total_decisions": len(self._decisions),
            "unique_situations": len(situations),
            "evidence_type_distribution": type_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._evidence.clear()
        self._decisions.clear()
        logger.info("soc_evidence_chain.cleared")
        return {"status": "cleared"}
