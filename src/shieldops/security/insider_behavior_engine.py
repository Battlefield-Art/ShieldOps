"""Insider Behavior Engine — behavioral baseline and deviation."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BehaviorType(StrEnum):
    LOGIN = "login"
    FILE_ACCESS = "file_access"
    DATA_TRANSFER = "data_transfer"
    PRIVILEGE_USE = "privilege_use"
    APPLICATION_USE = "application_use"


class DeviationSeverity(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BaselineStatus(StrEnum):
    BUILDING = "building"
    ESTABLISHED = "established"
    UPDATING = "updating"
    STALE = "stale"
    INVALID = "invalid"


# --- Models ---


class InsiderBehaviorRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    service_id: str = ""
    behavior_type: BehaviorType = BehaviorType.LOGIN
    deviation_severity: DeviationSeverity = DeviationSeverity.NONE
    baseline_status: BaselineStatus = BaselineStatus.BUILDING
    deviation_score: float = 0.0
    baseline_value: float = 0.0
    observed_value: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class InsiderBehaviorAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    analysis_score: float = 0.0
    behavior_type: BehaviorType = BehaviorType.LOGIN
    deviation_count: int = 0
    data_points: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class InsiderBehaviorReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_deviation_score: float = 0.0
    by_behavior: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_baseline: dict[str, int] = Field(default_factory=dict)
    high_risk_users: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class InsiderBehaviorEngine:
    """Build baselines and detect insider deviations."""

    def __init__(
        self,
        max_records: int = 200000,
        deviation_threshold: float = 0.7,
    ) -> None:
        self._max_records = max_records
        self._deviation_threshold = deviation_threshold
        self._records: list[InsiderBehaviorRecord] = []
        self._analyses: dict[str, InsiderBehaviorAnalysis] = {}
        logger.info(
            "insider_behavior_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        user_id: str = "",
        service_id: str = "",
        behavior_type: BehaviorType = (BehaviorType.LOGIN),
        deviation_severity: DeviationSeverity = (DeviationSeverity.NONE),
        baseline_status: BaselineStatus = (BaselineStatus.BUILDING),
        deviation_score: float = 0.0,
        baseline_value: float = 0.0,
        observed_value: float = 0.0,
        description: str = "",
    ) -> InsiderBehaviorRecord:
        record = InsiderBehaviorRecord(
            user_id=user_id,
            service_id=service_id,
            behavior_type=behavior_type,
            deviation_severity=deviation_severity,
            baseline_status=baseline_status,
            deviation_score=deviation_score,
            baseline_value=baseline_value,
            observed_value=observed_value,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "insider_behavior_engine.record_added",
            record_id=record.id,
            user_id=user_id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> InsiderBehaviorAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        user_recs = [r for r in self._records if r.user_id == rec.user_id]
        dev_count = sum(1 for r in user_recs if r.deviation_score > self._deviation_threshold)
        score = round(max(0.0, 100.0 - dev_count * 15), 2)
        analysis = InsiderBehaviorAnalysis(
            user_id=rec.user_id,
            analysis_score=score,
            behavior_type=rec.behavior_type,
            deviation_count=dev_count,
            data_points=len(user_recs),
            description=(f"Insider score {score} for {rec.user_id} ({dev_count} deviations)"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> InsiderBehaviorReport:
        by_b: dict[str, int] = {}
        by_s: dict[str, int] = {}
        by_bl: dict[str, int] = {}
        dev_scores: list[float] = []
        for r in self._records:
            by_b[r.behavior_type.value] = by_b.get(r.behavior_type.value, 0) + 1
            by_s[r.deviation_severity.value] = by_s.get(r.deviation_severity.value, 0) + 1
            by_bl[r.baseline_status.value] = by_bl.get(r.baseline_status.value, 0) + 1
            dev_scores.append(r.deviation_score)
        avg_dev = round(sum(dev_scores) / len(dev_scores), 2) if dev_scores else 0.0
        user_devs: dict[str, int] = {}
        for r in self._records:
            if r.deviation_score > self._deviation_threshold:
                user_devs[r.user_id] = user_devs.get(r.user_id, 0) + 1
        high_risk = sorted(
            user_devs,
            key=lambda k: user_devs.get(k, 0),
            reverse=True,
        )[:10]
        recs: list[str] = []
        crit = by_s.get(DeviationSeverity.CRITICAL.value, 0)
        if crit:
            recs.append(f"{crit} critical deviations found")
        if high_risk:
            recs.append(f"{len(high_risk)} high-risk users")
        if not recs:
            recs.append("Insider behavior within norms")
        return InsiderBehaviorReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_deviation_score=avg_dev,
            by_behavior=by_b,
            by_severity=by_s,
            by_baseline=by_bl,
            high_risk_users=high_risk,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        beh_dist: dict[str, int] = {}
        for r in self._records:
            k = r.behavior_type.value
            beh_dist[k] = beh_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "deviation_threshold": (self._deviation_threshold),
            "behavior_distribution": beh_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("insider_behavior_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def build_baseline(
        self,
    ) -> list[dict[str, Any]]:
        """Build behavioral baselines per user."""
        user_data: dict[str, dict[str, list[float]]] = {}
        for r in self._records:
            user_data.setdefault(r.user_id, {})
            user_data[r.user_id].setdefault(r.behavior_type.value, []).append(r.observed_value)
        results: list[dict[str, Any]] = []
        for uid, behaviors in user_data.items():
            for btype, vals in behaviors.items():
                avg = round(sum(vals) / len(vals), 2)
                results.append(
                    {
                        "user_id": uid,
                        "behavior_type": btype,
                        "baseline_avg": avg,
                        "sample_count": len(vals),
                    }
                )
        return results

    def score_deviation(
        self,
    ) -> list[dict[str, Any]]:
        """Score deviation from baseline per user."""
        user_scores: dict[str, list[float]] = {}
        for r in self._records:
            user_scores.setdefault(r.user_id, []).append(r.deviation_score)
        results: list[dict[str, Any]] = []
        for uid, scores in user_scores.items():
            avg = round(sum(scores) / len(scores), 2)
            mx = round(max(scores), 2)
            results.append(
                {
                    "user_id": uid,
                    "avg_deviation": avg,
                    "max_deviation": mx,
                    "sample_count": len(scores),
                }
            )
        results.sort(
            key=lambda x: x["max_deviation"],
            reverse=True,
        )
        return results

    def classify_insider_risk(
        self,
    ) -> list[dict[str, Any]]:
        """Classify insider risk level per user."""
        user_sev: dict[str, dict[str, int]] = {}
        for r in self._records:
            user_sev.setdefault(r.user_id, {})
            k = r.deviation_severity.value
            user_sev[r.user_id][k] = user_sev[r.user_id].get(k, 0) + 1
        results: list[dict[str, Any]] = []
        for uid, sevs in user_sev.items():
            crit = sevs.get("critical", 0)
            high = sevs.get("high", 0)
            risk = "low"
            if crit > 0:
                risk = "critical"
            elif high > 2:
                risk = "high"
            elif high > 0:
                risk = "medium"
            results.append(
                {
                    "user_id": uid,
                    "risk_level": risk,
                    "severity_counts": sevs,
                }
            )
        results.sort(
            key=lambda x: {"critical": 4, "high": 3, "medium": 2}.get(x["risk_level"], 1),
            reverse=True,
        )
        return results
