"""MultiAgentTrustEngine — Manages trust relationships between AI agents."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TrustStatus(StrEnum):
    ESTABLISHED = "established"
    PROVISIONAL = "provisional"
    REVOKED = "revoked"
    EXPIRED = "expired"


class VerificationMethod(StrEnum):
    CRYPTOGRAPHIC = "cryptographic"
    BEHAVIORAL = "behavioral"
    ATTESTATION = "attestation"
    MANUAL = "manual"


class TrustAction(StrEnum):
    GRANT = "grant"
    EXTEND = "extend"
    RESTRICT = "restrict"
    REVOKE = "revoke"


# --- Models ---


class TrustRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_agent: str = ""
    target_agent: str = ""
    trust_level: float = 0.0
    trust_status: TrustStatus = TrustStatus.PROVISIONAL
    verification_method: VerificationMethod = VerificationMethod.BEHAVIORAL
    trust_action: TrustAction = TrustAction.GRANT
    score: float = 0.0
    interaction_count: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class TrustAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    trust_status: TrustStatus = TrustStatus.PROVISIONAL
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class TrustReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_trust_status: dict[str, int] = Field(default_factory=dict)
    by_verification_method: dict[str, int] = Field(default_factory=dict)
    by_trust_action: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class MultiAgentTrustEngine:
    """Manages trust relationships between AI agents."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[TrustRecord] = []
        self._analyses: list[TrustAnalysis] = []
        logger.info(
            "multi_agent_trust_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        source_agent: str,
        target_agent: str,
        trust_level: float = 0.0,
        trust_status: TrustStatus = TrustStatus.PROVISIONAL,
        verification_method: VerificationMethod = VerificationMethod.BEHAVIORAL,
        trust_action: TrustAction = TrustAction.GRANT,
        score: float = 0.0,
        interaction_count: int = 0,
        service: str = "",
        team: str = "",
    ) -> TrustRecord:
        record = TrustRecord(
            source_agent=source_agent,
            target_agent=target_agent,
            trust_level=trust_level,
            trust_status=trust_status,
            verification_method=verification_method,
            trust_action=trust_action,
            score=score,
            interaction_count=interaction_count,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "multi_agent_trust_engine.record_added",
            record_id=record.id,
            source_agent=source_agent,
            target_agent=target_agent,
            trust_status=trust_status.value,
        )
        return record

    def get_record(self, record_id: str) -> TrustRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        trust_status: TrustStatus | None = None,
        verification_method: VerificationMethod | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[TrustRecord]:
        results = list(self._records)
        if trust_status is not None:
            results = [r for r in results if r.trust_status == trust_status]
        if verification_method is not None:
            results = [r for r in results if r.verification_method == verification_method]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        trust_status: TrustStatus = TrustStatus.PROVISIONAL,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> TrustAnalysis:
        analysis = TrustAnalysis(
            name=name,
            trust_status=trust_status,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "multi_agent_trust_engine.analysis_added",
            name=name,
            trust_status=trust_status.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def verify_trust_chain(self) -> list[dict[str, Any]]:
        """Verify trust chains between agents to detect broken or circular trust."""
        agent_trusts: dict[str, list[TrustRecord]] = {}
        for r in self._records:
            agent_trusts.setdefault(r.source_agent, []).append(r)
        results: list[dict[str, Any]] = []
        for source, records in agent_trusts.items():
            targets = {r.target_agent for r in records}
            chain_valid = all(r.trust_status == TrustStatus.ESTABLISHED for r in records)
            revoked = [r.target_agent for r in records if r.trust_status == TrustStatus.REVOKED]
            expired = [r.target_agent for r in records if r.trust_status == TrustStatus.EXPIRED]
            # Check for circular trust
            circular = []
            for t in targets:
                reverse = [
                    rec
                    for rec in self._records
                    if rec.source_agent == t and rec.target_agent == source
                ]
                if reverse:
                    circular.append(t)
            results.append(
                {
                    "source_agent": source,
                    "targets": sorted(targets),
                    "chain_valid": chain_valid and not circular,
                    "circular_trust": sorted(circular),
                    "revoked_targets": sorted(revoked),
                    "expired_targets": sorted(expired),
                    "trust_depth": len(targets),
                }
            )
        return sorted(results, key=lambda x: x["trust_depth"], reverse=True)

    def detect_trust_violations(self) -> list[dict[str, Any]]:
        """Detect trust violations such as revoked agents still communicating."""
        violations: list[dict[str, Any]] = []
        revoked_pairs: set[tuple[str, str]] = set()
        for r in self._records:
            if r.trust_status == TrustStatus.REVOKED:
                revoked_pairs.add((r.source_agent, r.target_agent))
        for r in self._records:
            if (
                r.trust_status == TrustStatus.ESTABLISHED
                and (r.source_agent, r.target_agent) in revoked_pairs
            ):
                violations.append(
                    {
                        "source_agent": r.source_agent,
                        "target_agent": r.target_agent,
                        "violation": "established_after_revocation",
                        "trust_level": r.trust_level,
                        "record_id": r.id,
                    }
                )
            if r.trust_status == TrustStatus.EXPIRED and r.interaction_count > 0:
                violations.append(
                    {
                        "source_agent": r.source_agent,
                        "target_agent": r.target_agent,
                        "violation": "interaction_on_expired_trust",
                        "interaction_count": r.interaction_count,
                        "record_id": r.id,
                    }
                )
        return sorted(violations, key=lambda x: x["violation"])

    def compute_trust_score(self) -> list[dict[str, Any]]:
        """Compute aggregate trust scores per agent based on all relationships."""
        agent_scores: dict[str, list[float]] = {}
        agent_statuses: dict[str, list[TrustStatus]] = {}
        for r in self._records:
            agent_scores.setdefault(r.source_agent, []).append(r.trust_level)
            agent_statuses.setdefault(r.source_agent, []).append(r.trust_status)
        results: list[dict[str, Any]] = []
        for agent, scores in agent_scores.items():
            statuses = agent_statuses[agent]
            established = sum(1 for s in statuses if s == TrustStatus.ESTABLISHED)
            revoked = sum(1 for s in statuses if s == TrustStatus.REVOKED)
            avg_trust = round(sum(scores) / len(scores), 2) if scores else 0.0
            health = "healthy" if revoked == 0 and avg_trust >= self._threshold else "degraded"
            if revoked > established:
                health = "critical"
            results.append(
                {
                    "agent_id": agent,
                    "avg_trust_level": avg_trust,
                    "total_relationships": len(scores),
                    "established_count": established,
                    "revoked_count": revoked,
                    "trust_health": health,
                }
            )
        return sorted(results, key=lambda x: x["avg_trust_level"])

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.trust_status.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "source_agent": r.source_agent,
                        "target_agent": r.target_agent,
                        "trust_status": r.trust_status.value,
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, agent_id: str) -> dict[str, Any]:
        matched = [
            r for r in self._records if r.source_agent == agent_id or r.target_agent == agent_id
        ]
        if not matched:
            return {"key": agent_id, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": agent_id,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> TrustReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.trust_status.value] = by_e1.get(r.trust_status.value, 0) + 1
            by_e2[r.verification_method.value] = by_e2.get(r.verification_method.value, 0) + 1
            by_e3[r.trust_action.value] = by_e3.get(r.trust_action.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["source_agent"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("Multi Agent Trust Engine is healthy")
        return TrustReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_trust_status=by_e1,
            by_verification_method=by_e2,
            by_trust_action=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("multi_agent_trust_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.trust_status.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "trust_status_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
