"""Adaptive Playbook Engine — manage dynamic playbook adaptation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AdaptationTrigger(StrEnum):
    FINDING_CHANGE = "finding_change"
    CONFIDENCE_DROP = "confidence_drop"
    NEW_IOC = "new_ioc"
    ANALYST_OVERRIDE = "analyst_override"


class AdaptationScope(StrEnum):
    STEP = "step"
    BRANCH = "branch"
    FULL_REWRITE = "full_rewrite"


class AdaptationOutcome(StrEnum):
    IMPROVED = "improved"
    NEUTRAL = "neutral"
    DEGRADED = "degraded"


# --- Models ---


class AdaptivePlaybookRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    adaptation_trigger: AdaptationTrigger = AdaptationTrigger.FINDING_CHANGE
    adaptation_scope: AdaptationScope = AdaptationScope.STEP
    adaptation_outcome: AdaptationOutcome = AdaptationOutcome.NEUTRAL
    score: float = 0.0
    before_score: float = 0.0
    after_score: float = 0.0
    playbook_id: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AdaptivePlaybookAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    adaptation_trigger: AdaptationTrigger = AdaptationTrigger.FINDING_CHANGE
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AdaptivePlaybookReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_adaptation_trigger: dict[str, int] = Field(default_factory=dict)
    by_adaptation_scope: dict[str, int] = Field(default_factory=dict)
    by_adaptation_outcome: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AdaptivePlaybookEngine:
    """Manage dynamic playbook adaptation."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AdaptivePlaybookRecord] = []
        self._analyses: list[AdaptivePlaybookAnalysis] = []
        logger.info(
            "adaptive_playbook.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ---

    def add_record(
        self,
        name: str,
        adaptation_trigger: AdaptationTrigger = (AdaptationTrigger.FINDING_CHANGE),
        adaptation_scope: AdaptationScope = (AdaptationScope.STEP),
        adaptation_outcome: AdaptationOutcome = (AdaptationOutcome.NEUTRAL),
        score: float = 0.0,
        before_score: float = 0.0,
        after_score: float = 0.0,
        playbook_id: str = "",
        service: str = "",
        team: str = "",
    ) -> AdaptivePlaybookRecord:
        record = AdaptivePlaybookRecord(
            name=name,
            adaptation_trigger=adaptation_trigger,
            adaptation_scope=adaptation_scope,
            adaptation_outcome=adaptation_outcome,
            score=score,
            before_score=before_score,
            after_score=after_score,
            playbook_id=playbook_id,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "adaptive_playbook.record_added",
            record_id=record.id,
            name=name,
            trigger=adaptation_trigger.value,
        )
        return record

    def get_record(self, record_id: str) -> AdaptivePlaybookRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        adaptation_trigger: (AdaptationTrigger | None) = None,
        adaptation_scope: (AdaptationScope | None) = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AdaptivePlaybookRecord]:
        results = list(self._records)
        if adaptation_trigger is not None:
            results = [r for r in results if r.adaptation_trigger == adaptation_trigger]
        if adaptation_scope is not None:
            results = [r for r in results if r.adaptation_scope == adaptation_scope]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        adaptation_trigger: AdaptationTrigger = (AdaptationTrigger.FINDING_CHANGE),
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AdaptivePlaybookAnalysis:
        analysis = AdaptivePlaybookAnalysis(
            name=name,
            adaptation_trigger=adaptation_trigger,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "adaptive_playbook.analysis_added",
            name=name,
            trigger=adaptation_trigger.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations ---

    def evaluate_adaptation_need(
        self,
    ) -> list[dict[str, Any]]:
        """Evaluate which playbooks need adaptation."""
        pb_data: dict[str, list[AdaptivePlaybookRecord]] = {}
        for r in self._records:
            if r.playbook_id:
                pb_data.setdefault(r.playbook_id, []).append(r)
        results: list[dict[str, Any]] = []
        for pid, records in pb_data.items():
            degraded = sum(1 for r in records if r.adaptation_outcome == AdaptationOutcome.DEGRADED)
            total = len(records)
            degrade_pct = round(degraded / total * 100, 1)
            avg_score = round(
                sum(r.score for r in records) / total,
                2,
            )
            needs_adapt = degrade_pct > 20 or avg_score < self._threshold
            scope = (
                AdaptationScope.FULL_REWRITE
                if degrade_pct > 50
                else (AdaptationScope.BRANCH if degrade_pct > 20 else AdaptationScope.STEP)
            )
            results.append(
                {
                    "playbook_id": pid,
                    "needs_adaptation": needs_adapt,
                    "degradation_pct": degrade_pct,
                    "avg_score": avg_score,
                    "scope": scope.value,
                    "adaptations": total,
                }
            )
        return sorted(
            results,
            key=lambda x: x["degradation_pct"],
            reverse=True,
        )

    def apply_adaptation(
        self,
    ) -> list[dict[str, Any]]:
        """Track adaptation application results."""
        pb_data: dict[str, list[AdaptivePlaybookRecord]] = {}
        for r in self._records:
            if r.playbook_id:
                pb_data.setdefault(r.playbook_id, []).append(r)
        results: list[dict[str, Any]] = []
        for pid, records in pb_data.items():
            improved = sum(1 for r in records if r.adaptation_outcome == AdaptationOutcome.IMPROVED)
            total = len(records)
            improvements = [r.after_score - r.before_score for r in records if r.after_score > 0]
            avg_delta = (
                round(
                    sum(improvements) / len(improvements),
                    2,
                )
                if improvements
                else 0.0
            )
            results.append(
                {
                    "playbook_id": pid,
                    "total_adaptations": total,
                    "improved_count": improved,
                    "improvement_rate": round(improved / total * 100, 1),
                    "avg_score_delta": avg_delta,
                }
            )
        return sorted(
            results,
            key=lambda x: x["improvement_rate"],
        )

    def measure_adaptation_impact(
        self,
    ) -> dict[str, Any]:
        """Measure overall adaptation impact."""
        if not self._records:
            return {"impact": 0.0, "total": 0}
        outcome_ct: dict[str, int] = {}
        for r in self._records:
            o = r.adaptation_outcome.value
            outcome_ct[o] = outcome_ct.get(o, 0) + 1
        total = len(self._records)
        improved = outcome_ct.get("improved", 0)
        degraded = outcome_ct.get("degraded", 0)
        net_impact = round((improved - degraded) / total * 100, 1)
        deltas = [r.after_score - r.before_score for r in self._records if r.after_score > 0]
        avg_delta = round(sum(deltas) / len(deltas), 2) if deltas else 0.0
        return {
            "net_impact_pct": net_impact,
            "avg_score_delta": avg_delta,
            "total_adaptations": total,
            "outcome_distribution": outcome_ct,
            "positive": improved > degraded,
        }

    # -- standard methods ---

    def analyze_distribution(
        self,
    ) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.adaptation_trigger.value
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
                        "trigger": (r.adaptation_trigger.value),
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

    def generate_report(
        self,
    ) -> AdaptivePlaybookReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            k1 = r.adaptation_trigger.value
            by_e1[k1] = by_e1.get(k1, 0) + 1
            k2 = r.adaptation_scope.value
            by_e2[k2] = by_e2.get(k2, 0) + 1
            k3 = r.adaptation_outcome.value
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
            recs.append("Adaptive Playbook Engine healthy")
        return AdaptivePlaybookReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_adaptation_trigger=by_e1,
            by_adaptation_scope=by_e2,
            by_adaptation_outcome=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("adaptive_playbook.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.adaptation_trigger.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "adaptation_trigger_dist": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
