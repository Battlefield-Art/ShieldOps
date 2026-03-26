"""ZTNA Trust Scorer — calculate zero trust access trust scores."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class TrustFactor(StrEnum):
    IDENTITY = "identity"
    DEVICE = "device"
    BEHAVIOR = "behavior"
    LOCATION = "location"
    CONTEXT = "context"


class TrustLevel(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    ZERO = "zero"


class AccessDecision(StrEnum):
    ALLOW = "allow"
    CHALLENGE = "challenge"
    DENY = "deny"


# --- Models ---


class ZTNATrustRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    trust_factor: TrustFactor = TrustFactor.IDENTITY
    trust_level: TrustLevel = TrustLevel.MEDIUM
    access_decision: AccessDecision = AccessDecision.CHALLENGE
    score: float = 0.0
    factor_score: float = 0.0
    identity_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ZTNATrustAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    trust_factor: TrustFactor = TrustFactor.IDENTITY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ZTNATrustReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_trust_factor: dict[str, int] = Field(default_factory=dict)
    by_trust_level: dict[str, int] = Field(default_factory=dict)
    by_access_decision: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ZTNATrustScorerEngine:
    """Calculate zero trust access trust scores."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[ZTNATrustRecord] = []
        self._analyses: list[ZTNATrustAnalysis] = []
        logger.info(
            "ztna_trust_scorer.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ---

    def add_record(
        self,
        name: str,
        trust_factor: TrustFactor = (TrustFactor.IDENTITY),
        trust_level: TrustLevel = TrustLevel.MEDIUM,
        access_decision: AccessDecision = (AccessDecision.CHALLENGE),
        score: float = 0.0,
        factor_score: float = 0.0,
        identity_id: str = "",
        service: str = "",
        team: str = "",
    ) -> ZTNATrustRecord:
        record = ZTNATrustRecord(
            name=name,
            trust_factor=trust_factor,
            trust_level=trust_level,
            access_decision=access_decision,
            score=score,
            factor_score=factor_score,
            identity_id=identity_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ztna_trust_scorer.record_added",
            record_id=record.id,
            name=name,
            trust_factor=trust_factor.value,
        )
        return record

    def get_record(self, record_id: str) -> ZTNATrustRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        trust_factor: TrustFactor | None = None,
        trust_level: TrustLevel | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ZTNATrustRecord]:
        results = list(self._records)
        if trust_factor is not None:
            results = [r for r in results if r.trust_factor == trust_factor]
        if trust_level is not None:
            results = [r for r in results if r.trust_level == trust_level]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        trust_factor: TrustFactor = (TrustFactor.IDENTITY),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ZTNATrustAnalysis:
        analysis = ZTNATrustAnalysis(
            name=name,
            trust_factor=trust_factor,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "ztna_trust_scorer.analysis_added",
            name=name,
            trust_factor=trust_factor.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ---

    _FACTOR_WEIGHTS = {
        "identity": 0.30,
        "device": 0.25,
        "behavior": 0.25,
        "location": 0.10,
        "context": 0.10,
    }

    def calculate_trust_score(
        self,
    ) -> list[dict[str, Any]]:
        """Calculate composite trust score per identity."""
        id_data: dict[str, list[ZTNATrustRecord]] = {}
        for r in self._records:
            if r.identity_id:
                id_data.setdefault(r.identity_id, []).append(r)
        results: list[dict[str, Any]] = []
        for iid, records in id_data.items():
            weighted = 0.0
            weight_total = 0.0
            factor_scores: dict[str, float] = {}
            for r in records:
                w = self._FACTOR_WEIGHTS.get(r.trust_factor.value, 0.1)
                weighted += r.factor_score * w
                weight_total += w
                factor_scores[r.trust_factor.value] = r.factor_score
            composite = round(weighted / weight_total, 2) if weight_total else 0.0
            level = (
                "high"
                if composite >= 80
                else ("medium" if composite >= 50 else ("low" if composite >= 20 else "zero"))
            )
            decision = (
                "allow" if level == "high" else ("challenge" if level == "medium" else "deny")
            )
            results.append(
                {
                    "identity_id": iid,
                    "trust_score": composite,
                    "trust_level": level,
                    "access_decision": decision,
                    "factor_scores": factor_scores,
                }
            )
        return sorted(
            results,
            key=lambda x: x["trust_score"],
        )

    def evaluate_risk_signals(
        self,
    ) -> list[dict[str, Any]]:
        """Evaluate risk signals across factors."""
        factor_data: dict[str, list[ZTNATrustRecord]] = {}
        for r in self._records:
            factor_data.setdefault(r.trust_factor.value, []).append(r)
        results: list[dict[str, Any]] = []
        for factor, records in factor_data.items():
            scores = [r.factor_score for r in records]
            avg = round(sum(scores) / len(scores), 2)
            low_ct = sum(1 for r in records if r.trust_level in (TrustLevel.LOW, TrustLevel.ZERO))
            results.append(
                {
                    "factor": factor,
                    "avg_score": avg,
                    "sample_count": len(records),
                    "low_trust_count": low_ct,
                    "low_trust_pct": round(
                        low_ct / len(records) * 100,
                        1,
                    ),
                    "weight": (self._FACTOR_WEIGHTS.get(factor, 0.1)),
                }
            )
        return sorted(results, key=lambda x: x["avg_score"])

    def enforce_adaptive_policy(
        self,
    ) -> list[dict[str, Any]]:
        """Enforce adaptive access policies."""
        id_data: dict[str, list[ZTNATrustRecord]] = {}
        for r in self._records:
            if r.identity_id:
                id_data.setdefault(r.identity_id, []).append(r)
        enforcements: list[dict[str, Any]] = []
        for iid, records in id_data.items():
            latest = records[-1]
            deny_ct = sum(1 for r in records if r.access_decision == AccessDecision.DENY)
            total = len(records)
            deny_pct = round(deny_ct / total * 100, 1)
            policy = "block" if deny_pct > 50 else ("step_up_auth" if deny_pct > 20 else "normal")
            enforcements.append(
                {
                    "identity_id": iid,
                    "current_level": (latest.trust_level.value),
                    "deny_rate_pct": deny_pct,
                    "policy_action": policy,
                    "evaluations": total,
                }
            )
        return sorted(
            enforcements,
            key=lambda x: x["deny_rate_pct"],
            reverse=True,
        )

    # -- standard methods ---

    def analyze_distribution(
        self,
    ) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.trust_factor.value
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
                        "name": r.name,
                        "trust_factor": (r.trust_factor.value),
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(self) -> list[dict[str, Any]]:
        svc: dict[str, list[float]] = {}
        for r in self._records:
            svc.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for s, scores in svc.items():
            results.append(
                {
                    "service": s,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats ---

    def generate_report(self) -> ZTNATrustReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            k1 = r.trust_factor.value
            by_e1[k1] = by_e1.get(k1, 0) + 1
            k2 = r.trust_level.value
            by_e2[k2] = by_e2.get(k2, 0) + 1
            k3 = r.access_decision.value
            by_e3[k3] = by_e3.get(k3, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("ZTNA Trust Scorer is healthy")
        return ZTNATrustReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_trust_factor=by_e1,
            by_trust_level=by_e2,
            by_access_decision=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("ztna_trust_scorer.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.trust_factor.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "trust_factor_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
