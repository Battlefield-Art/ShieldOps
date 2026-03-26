"""Identity Attack Chain — multi-step identity attacks."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ChainPhase(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"


class EscalationPath(StrEnum):
    ROLE_ASSUMPTION = "role_assumption"
    TOKEN_THEFT = "token_theft"  # noqa: S105
    SERVICE_ACCOUNT = "service_account"
    OAUTH_ABUSE = "oauth_abuse"
    ADMIN_COMPROMISE = "admin_compromise"


class ChainStatus(StrEnum):
    ACTIVE = "active"
    CONTAINED = "contained"
    MITIGATED = "mitigated"
    MONITORING = "monitoring"
    CLOSED = "closed"


# --- Models ---


class AttackChainRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    chain_id: str = ""
    phase: ChainPhase = ChainPhase.RECONNAISSANCE
    path: EscalationPath = EscalationPath.ROLE_ASSUMPTION
    status: ChainStatus = ChainStatus.ACTIVE
    identity_id: str = ""
    target_identity: str = ""
    steps_completed: int = 0
    confidence: float = 0.0
    pivot_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AttackChainAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    chain_id: str = ""
    phase: ChainPhase = ChainPhase.RECONNAISSANCE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AttackChainReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    active_chains: int = 0
    avg_confidence: float = 0.0
    by_phase: dict[str, int] = Field(default_factory=dict)
    by_path: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class IdentityAttackChainEngine:
    """Track multi-step identity attack chains."""

    def __init__(
        self,
        max_records: int = 200000,
        confidence_threshold: float = 0.7,
    ) -> None:
        self._max_records = max_records
        self._threshold = confidence_threshold
        self._records: list[AttackChainRecord] = []
        self._analyses: list[AttackChainAnalysis] = []
        logger.info(
            "identity_attack_chain.initialized",
            max_records=max_records,
            confidence_threshold=confidence_threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        chain_id: str,
        phase: ChainPhase = (ChainPhase.RECONNAISSANCE),
        path: EscalationPath = (EscalationPath.ROLE_ASSUMPTION),
        status: ChainStatus = ChainStatus.ACTIVE,
        identity_id: str = "",
        target_identity: str = "",
        steps_completed: int = 0,
        confidence: float = 0.0,
        pivot_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> AttackChainRecord:
        record = AttackChainRecord(
            chain_id=chain_id,
            phase=phase,
            path=path,
            status=status,
            identity_id=identity_id,
            target_identity=target_identity,
            steps_completed=steps_completed,
            confidence=confidence,
            pivot_count=pivot_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "identity_attack_chain.record_added",
            record_id=record.id,
            chain_id=chain_id,
            phase=phase.value,
            status=status.value,
        )
        return record

    def get_record(self, record_id: str) -> AttackChainRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        phase: ChainPhase | None = None,
        status: ChainStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AttackChainRecord]:
        results = list(self._records)
        if phase is not None:
            results = [r for r in results if r.phase == phase]
        if status is not None:
            results = [r for r in results if r.status == status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def process(self, chain_id: str) -> AttackChainAnalysis:
        matched = [r for r in self._records if r.chain_id == chain_id]
        scores = [r.confidence for r in matched]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        breached = avg > self._threshold
        analysis = AttackChainAnalysis(
            chain_id=chain_id,
            phase=(matched[-1].phase if matched else ChainPhase.RECONNAISSANCE),
            analysis_score=avg,
            threshold=self._threshold,
            breached=breached,
            description=(f"Confidence {avg} for {chain_id}"),
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    # -- domain operations ------------------------------------

    def build_attack_chain(
        self,
        chain_id: str,
        identity_id: str,
        phases: list[ChainPhase] | None = None,
    ) -> dict[str, Any]:
        """Build an attack chain from events."""
        if phases is None:
            phases = [ChainPhase.RECONNAISSANCE]
        for i, phase in enumerate(phases):
            self.add_record(
                chain_id=chain_id,
                phase=phase,
                identity_id=identity_id,
                steps_completed=i + 1,
                confidence=round(0.3 + i * 0.15, 2),
            )
        analysis = self.process(chain_id)
        return {
            "chain_id": chain_id,
            "identity_id": identity_id,
            "phases": [p.value for p in phases],
            "total_steps": len(phases),
            "analysis_score": (analysis.analysis_score),
            "breached": analysis.breached,
        }

    def identify_pivot_points(self, chain_id: str) -> dict[str, Any]:
        """Identify pivot points in a chain."""
        matched = [r for r in self._records if r.chain_id == chain_id]
        pivots: list[dict[str, Any]] = []
        for r in matched:
            if r.pivot_count > 0 or r.phase in (
                ChainPhase.LATERAL_MOVEMENT,
                ChainPhase.PRIVILEGE_ESCALATION,
            ):
                pivots.append(
                    {
                        "record_id": r.id,
                        "phase": r.phase.value,
                        "path": r.path.value,
                        "identity_id": r.identity_id,
                        "target": r.target_identity,
                        "pivot_count": r.pivot_count,
                        "confidence": r.confidence,
                    }
                )
        return {
            "chain_id": chain_id,
            "total_records": len(matched),
            "pivot_points": len(pivots),
            "pivots": pivots,
        }

    def predict_next_phase(self, chain_id: str) -> dict[str, Any]:
        """Predict next phase in attack chain."""
        matched = [r for r in self._records if r.chain_id == chain_id]
        if not matched:
            return {
                "chain_id": chain_id,
                "found": False,
            }
        phase_order = list(ChainPhase)
        current = matched[-1].phase
        idx = phase_order.index(current)
        predicted = phase_order[idx + 1] if idx < len(phase_order) - 1 else current
        avg_conf = round(
            sum(r.confidence for r in matched) / len(matched),
            4,
        )
        return {
            "chain_id": chain_id,
            "current_phase": current.value,
            "predicted_next": predicted.value,
            "steps_so_far": len(matched),
            "avg_confidence": avg_conf,
            "at_final_phase": idx >= len(phase_order) - 1,
        }

    # -- report / stats ----------------------------------------

    def generate_report(
        self,
    ) -> AttackChainReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.phase.value] = by_e1.get(r.phase.value, 0) + 1
            by_e2[r.path.value] = by_e2.get(r.path.value, 0) + 1
            by_e3[r.status.value] = by_e3.get(r.status.value, 0) + 1
        scores = [r.confidence for r in self._records]
        avg_conf = round(sum(scores) / len(scores), 2) if scores else 0.0
        active_ct = sum(1 for r in self._records if r.status == ChainStatus.ACTIVE)
        gap_count = sum(
            1
            for r in self._records
            if r.confidence > self._threshold and r.status == ChainStatus.ACTIVE
        )
        top_gaps = [
            r.chain_id
            for r in self._records
            if r.confidence > self._threshold and r.status == ChainStatus.ACTIVE
        ][:5]
        recs: list[str] = []
        if active_ct > 0:
            recs.append(f"{active_ct} active chain(s)")
        if gap_count > 0:
            recs.append(f"{gap_count} high-confidence active chain(s)")
        if not recs:
            recs.append("Attack Chain Engine is healthy")
        return AttackChainReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            active_chains=active_ct,
            avg_confidence=avg_conf,
            by_phase=by_e1,
            by_path=by_e2,
            by_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("identity_attack_chain.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.phase.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "phase_distribution": e1_dist,
            "unique_chains": len({r.chain_id for r in self._records}),
            "active_chains": sum(1 for r in self._records if r.status == ChainStatus.ACTIVE),
        }
