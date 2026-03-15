"""DetectionRuleLifecycleEngine — Track detection rule lifecycle from draft to retirement."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RuleLifecyclePhase(StrEnum):
    DRAFT = "draft"
    TESTING = "testing"
    ACTIVE = "active"
    TUNING = "tuning"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class RuleQuality(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"


class MaintenanceAction(StrEnum):
    TUNE = "tune"
    REWRITE = "rewrite"
    RETIRE = "retire"
    PROMOTE = "promote"


# --- Models ---


class DetectionRuleLifecycleRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    rule_lifecycle_phase: RuleLifecyclePhase = RuleLifecyclePhase.DRAFT
    rule_quality: RuleQuality = RuleQuality.GOOD
    maintenance_action: MaintenanceAction = MaintenanceAction.TUNE
    score: float = 0.0
    true_positives: int = 0
    false_positives: int = 0
    days_since_update: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class DetectionRuleLifecycleAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    rule_lifecycle_phase: RuleLifecyclePhase = RuleLifecyclePhase.DRAFT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DetectionRuleLifecycleReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_rule_lifecycle_phase: dict[str, int] = Field(default_factory=dict)
    by_rule_quality: dict[str, int] = Field(default_factory=dict)
    by_maintenance_action: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class DetectionRuleLifecycleEngine:
    """Track detection rule lifecycle from draft to retirement engine."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[DetectionRuleLifecycleRecord] = []
        self._analyses: list[DetectionRuleLifecycleAnalysis] = []
        logger.info(
            "detection_rule_lifecycle_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        rule_lifecycle_phase: RuleLifecyclePhase = RuleLifecyclePhase.DRAFT,
        rule_quality: RuleQuality = RuleQuality.GOOD,
        maintenance_action: MaintenanceAction = MaintenanceAction.TUNE,
        score: float = 0.0,
        true_positives: int = 0,
        false_positives: int = 0,
        days_since_update: int = 0,
        service: str = "",
        team: str = "",
    ) -> DetectionRuleLifecycleRecord:
        record = DetectionRuleLifecycleRecord(
            name=name,
            rule_lifecycle_phase=rule_lifecycle_phase,
            rule_quality=rule_quality,
            maintenance_action=maintenance_action,
            score=score,
            true_positives=true_positives,
            false_positives=false_positives,
            days_since_update=days_since_update,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "detection_rule_lifecycle_engine.record_added",
            record_id=record.id,
            name=name,
            rule_lifecycle_phase=rule_lifecycle_phase.value,
            rule_quality=rule_quality.value,
        )
        return record

    def get_record(self, record_id: str) -> DetectionRuleLifecycleRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        rule_lifecycle_phase: RuleLifecyclePhase | None = None,
        rule_quality: RuleQuality | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[DetectionRuleLifecycleRecord]:
        results = list(self._records)
        if rule_lifecycle_phase is not None:
            results = [r for r in results if r.rule_lifecycle_phase == rule_lifecycle_phase]
        if rule_quality is not None:
            results = [r for r in results if r.rule_quality == rule_quality]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        rule_lifecycle_phase: RuleLifecyclePhase = RuleLifecyclePhase.DRAFT,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> DetectionRuleLifecycleAnalysis:
        analysis = DetectionRuleLifecycleAnalysis(
            name=name,
            rule_lifecycle_phase=rule_lifecycle_phase,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "detection_rule_lifecycle_engine.analysis_added",
            name=name,
            rule_lifecycle_phase=rule_lifecycle_phase.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def identify_stale_rules(self) -> list[dict[str, Any]]:
        """Identify rules that haven't been updated in a long time."""
        stale: list[dict[str, Any]] = []
        for r in self._records:
            if r.days_since_update > 90:
                stale.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "team": r.team,
                        "days_since_update": r.days_since_update,
                        "rule_lifecycle_phase": r.rule_lifecycle_phase.value,
                        "rule_quality": r.rule_quality.value,
                        "recommendation": ("retire" if r.days_since_update > 365 else "review"),
                    }
                )
        return sorted(stale, key=lambda x: x["days_since_update"], reverse=True)

    def compute_rule_quality_score(self) -> list[dict[str, Any]]:
        """Compute quality score for each rule based on TP/FP ratio."""
        rule_data: dict[str, list[DetectionRuleLifecycleRecord]] = {}
        for r in self._records:
            rule_data.setdefault(r.name, []).append(r)
        results: list[dict[str, Any]] = []
        for name, records in rule_data.items():
            total_tp = sum(r.true_positives for r in records)
            total_fp = sum(r.false_positives for r in records)
            precision = (
                round(total_tp / (total_tp + total_fp), 4) if (total_tp + total_fp) > 0 else 0.0
            )
            avg_score = round(sum(r.score for r in records) / len(records), 2)
            quality_label = "excellent"
            if precision < 0.5:
                quality_label = "poor"
            elif precision < 0.7:
                quality_label = "fair"
            elif precision < 0.9:
                quality_label = "good"
            results.append(
                {
                    "rule_name": name,
                    "true_positives": total_tp,
                    "false_positives": total_fp,
                    "precision": precision,
                    "avg_score": avg_score,
                    "quality_label": quality_label,
                    "record_count": len(records),
                }
            )
        return sorted(results, key=lambda x: x["precision"])

    def recommend_maintenance_actions(self) -> list[dict[str, Any]]:
        """Recommend maintenance actions for detection rules."""
        recommendations: list[dict[str, Any]] = []
        for r in self._records:
            if r.rule_quality == RuleQuality.POOR:
                recommendations.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "issue": "poor_quality",
                        "priority": "high",
                        "action": MaintenanceAction.REWRITE.value,
                        "suggestion": f"Rewrite rule {r.name} due to poor quality",
                    }
                )
            elif r.rule_lifecycle_phase == RuleLifecyclePhase.DEPRECATED:
                recommendations.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "issue": "deprecated",
                        "priority": "medium",
                        "action": MaintenanceAction.RETIRE.value,
                        "suggestion": f"Retire deprecated rule {r.name}",
                    }
                )
            elif r.days_since_update > 180 and r.rule_quality == RuleQuality.FAIR:
                recommendations.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "issue": "stale_fair_quality",
                        "priority": "medium",
                        "action": MaintenanceAction.TUNE.value,
                        "suggestion": (
                            f"Tune stale rule {r.name} "
                            f"(fair quality, {r.days_since_update} days old)"
                        ),
                    }
                )
            elif r.score < self._threshold:
                recommendations.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "issue": "low_score",
                        "priority": "low",
                        "action": MaintenanceAction.TUNE.value,
                        "suggestion": f"Tune rule {r.name} (score: {r.score})",
                    }
                )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else 1 if x["priority"] == "medium" else 2,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.rule_lifecycle_phase.value
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
                        "rule_lifecycle_phase": r.rule_lifecycle_phase.value,
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

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> DetectionRuleLifecycleReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.rule_lifecycle_phase.value] = by_e1.get(r.rule_lifecycle_phase.value, 0) + 1
            by_e2[r.rule_quality.value] = by_e2.get(r.rule_quality.value, 0) + 1
            by_e3[r.maintenance_action.value] = by_e3.get(r.maintenance_action.value, 0) + 1
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
            recs.append("Detection Rule Lifecycle Engine is healthy")
        return DetectionRuleLifecycleReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_rule_lifecycle_phase=by_e1,
            by_rule_quality=by_e2,
            by_maintenance_action=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("detection_rule_lifecycle_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.rule_lifecycle_phase.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "rule_lifecycle_phase_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
