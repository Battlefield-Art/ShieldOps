"""Security Playbook Selector Engine —
match security alerts to appropriate response playbooks based on
MITRE tactics, risk level, and past effectiveness."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PlaybookCategory(StrEnum):
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    INVESTIGATION = "investigation"


class MatchStrategy(StrEnum):
    MITRE_BASED = "mitre_based"
    RISK_BASED = "risk_based"
    HISTORICAL = "historical"
    ENSEMBLE = "ensemble"


class SelectionConfidence(StrEnum):
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    NO_MATCH = "no_match"


# --- Models ---


class PlaybookSelectorRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_type: str = ""
    playbook_id: str = ""
    playbook_category: PlaybookCategory = PlaybookCategory.INVESTIGATION
    match_strategy: MatchStrategy = MatchStrategy.ENSEMBLE
    selection_confidence: SelectionConfidence = SelectionConfidence.NO_MATCH
    mitre_tactic: str = ""
    mitre_technique: str = ""
    risk_level: float = 0.0
    success_rate: float = 0.0
    execution_count: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PlaybookSelectorAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_type: str = ""
    recommended_playbook: str = ""
    match_strategy: MatchStrategy = MatchStrategy.ENSEMBLE
    selection_confidence: SelectionConfidence = SelectionConfidence.NO_MATCH
    confidence_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class PlaybookSelectorReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_success_rate: float = 0.0
    by_playbook_category: dict[str, int] = Field(default_factory=dict)
    by_match_strategy: dict[str, int] = Field(default_factory=dict)
    by_selection_confidence: dict[str, int] = Field(default_factory=dict)
    unmatched_alert_types: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class SecurityPlaybookSelectorEngine:
    """Match security alerts to appropriate response playbooks based on
    MITRE tactics, risk level, and past effectiveness."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[PlaybookSelectorRecord] = []
        self._analyses: dict[str, PlaybookSelectorAnalysis] = {}
        logger.info(
            "security_playbook_selector_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        alert_type: str = "",
        playbook_id: str = "",
        playbook_category: PlaybookCategory = PlaybookCategory.INVESTIGATION,
        match_strategy: MatchStrategy = MatchStrategy.ENSEMBLE,
        selection_confidence: SelectionConfidence = SelectionConfidence.NO_MATCH,
        mitre_tactic: str = "",
        mitre_technique: str = "",
        risk_level: float = 0.0,
        success_rate: float = 0.0,
        execution_count: int = 0,
        description: str = "",
    ) -> PlaybookSelectorRecord:
        record = PlaybookSelectorRecord(
            alert_type=alert_type,
            playbook_id=playbook_id,
            playbook_category=playbook_category,
            match_strategy=match_strategy,
            selection_confidence=selection_confidence,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            risk_level=risk_level,
            success_rate=success_rate,
            execution_count=execution_count,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "playbook_selector.record_added",
            record_id=record.id,
            alert_type=alert_type,
        )
        return record

    def process(self, key: str) -> PlaybookSelectorAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        confidence_score = round(rec.success_rate * rec.risk_level, 4)
        if rec.success_rate >= 0.8:
            confidence = SelectionConfidence.HIGH
        elif rec.success_rate >= 0.5:
            confidence = SelectionConfidence.MODERATE
        elif rec.playbook_id:
            confidence = SelectionConfidence.LOW
        else:
            confidence = SelectionConfidence.NO_MATCH
        analysis = PlaybookSelectorAnalysis(
            alert_type=rec.alert_type,
            recommended_playbook=rec.playbook_id,
            match_strategy=rec.match_strategy,
            selection_confidence=confidence,
            confidence_score=confidence_score,
            description=(
                f"Alert {rec.alert_type} -> playbook {rec.playbook_id} "
                f"confidence={confidence.value}"
            ),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> PlaybookSelectorReport:
        by_cat: dict[str, int] = {}
        by_strat: dict[str, int] = {}
        by_conf: dict[str, int] = {}
        rates: list[float] = []
        for r in self._records:
            by_cat[r.playbook_category.value] = by_cat.get(r.playbook_category.value, 0) + 1
            by_strat[r.match_strategy.value] = by_strat.get(r.match_strategy.value, 0) + 1
            by_conf[r.selection_confidence.value] = by_conf.get(r.selection_confidence.value, 0) + 1
            rates.append(r.success_rate)
        avg_rate = round(sum(rates) / len(rates), 4) if rates else 0.0
        unmatched = list(
            {
                r.alert_type
                for r in self._records
                if r.selection_confidence == SelectionConfidence.NO_MATCH and r.alert_type
            }
        )[:10]
        recs: list[str] = []
        if unmatched:
            recs.append(f"{len(unmatched)} alert types have no matching playbook")
        if avg_rate < 0.5:
            recs.append("Average playbook success rate is below 50%")
        if not recs:
            recs.append("Playbook selection operating within normal parameters")
        return PlaybookSelectorReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_success_rate=avg_rate,
            by_playbook_category=by_cat,
            by_match_strategy=by_strat,
            by_selection_confidence=by_conf,
            unmatched_alert_types=unmatched,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        cat_dist: dict[str, int] = {}
        for r in self._records:
            cat_dist[r.playbook_category.value] = cat_dist.get(r.playbook_category.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "playbook_category_distribution": cat_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("security_playbook_selector_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def match_alert_to_playbook(
        self,
        alert_type: str = "",
        mitre_tactic: str = "",
    ) -> list[dict[str, Any]]:
        """Find best playbook match for a given alert type and MITRE tactic."""
        candidates: list[PlaybookSelectorRecord] = []
        for r in self._records:
            type_match = alert_type and r.alert_type == alert_type
            tactic_match = mitre_tactic and r.mitre_tactic == mitre_tactic
            if type_match or tactic_match:
                candidates.append(r)
        if not candidates:
            return [
                {
                    "alert_type": alert_type,
                    "mitre_tactic": mitre_tactic,
                    "match": "none",
                    "confidence": SelectionConfidence.NO_MATCH.value,
                }
            ]
        scored: list[dict[str, Any]] = []
        for c in candidates:
            score = c.success_rate
            if c.alert_type == alert_type and c.mitre_tactic == mitre_tactic:
                score += 0.3
            elif c.alert_type == alert_type:
                score += 0.2
            elif c.mitre_tactic == mitre_tactic:
                score += 0.1
            scored.append(
                {
                    "playbook_id": c.playbook_id,
                    "playbook_category": c.playbook_category.value,
                    "match_score": round(min(score, 1.0), 4),
                    "success_rate": c.success_rate,
                    "execution_count": c.execution_count,
                    "confidence": (
                        SelectionConfidence.HIGH.value
                        if score >= 0.8
                        else SelectionConfidence.MODERATE.value
                        if score >= 0.5
                        else SelectionConfidence.LOW.value
                    ),
                }
            )
        scored.sort(key=lambda x: x["match_score"], reverse=True)
        return scored

    def rank_playbooks_by_effectiveness(self) -> list[dict[str, Any]]:
        """Rank playbooks by historical success rate."""
        playbook_data: dict[str, list[PlaybookSelectorRecord]] = {}
        for r in self._records:
            if r.playbook_id:
                playbook_data.setdefault(r.playbook_id, []).append(r)
        results: list[dict[str, Any]] = []
        for pid, recs in playbook_data.items():
            avg_success = round(sum(r.success_rate for r in recs) / len(recs), 4)
            total_execs = sum(r.execution_count for r in recs)
            categories = list({r.playbook_category.value for r in recs})
            results.append(
                {
                    "playbook_id": pid,
                    "avg_success_rate": avg_success,
                    "total_executions": total_execs,
                    "categories": categories,
                    "record_count": len(recs),
                    "rank_tier": (
                        "top" if avg_success >= 0.8 else "mid" if avg_success >= 0.5 else "low"
                    ),
                }
            )
        results.sort(key=lambda x: x["avg_success_rate"], reverse=True)
        return results

    def identify_playbook_gaps(self) -> list[dict[str, Any]]:
        """Find alert types with no matching playbook."""
        alert_playbooks: dict[str, set[str]] = {}
        for r in self._records:
            if r.alert_type:
                alert_playbooks.setdefault(r.alert_type, set())
                if r.playbook_id:
                    alert_playbooks[r.alert_type].add(r.playbook_id)
        gaps: list[dict[str, Any]] = []
        for alert_type, playbooks in alert_playbooks.items():
            matching_recs = [r for r in self._records if r.alert_type == alert_type]
            avg_risk = round(
                sum(r.risk_level for r in matching_recs) / len(matching_recs),
                4,
            )
            if not playbooks:
                gaps.append(
                    {
                        "alert_type": alert_type,
                        "playbook_count": 0,
                        "avg_risk_level": avg_risk,
                        "occurrence_count": len(matching_recs),
                        "gap_severity": (
                            "critical"
                            if avg_risk >= 0.8
                            else "high"
                            if avg_risk >= 0.5
                            else "medium"
                        ),
                    }
                )
        gaps.sort(key=lambda x: x["avg_risk_level"], reverse=True)
        return gaps
