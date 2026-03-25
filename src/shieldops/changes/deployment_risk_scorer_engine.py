"""Deployment Risk Scorer Engine — score deployment risk using historical patterns."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class DeploymentType(StrEnum):
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    CANARY = "canary"
    RECREATE = "recreate"
    FEATURE_FLAG = "feature_flag"


class RiskFactor(StrEnum):
    FRIDAY_DEPLOY = "friday_deploy"
    LARGE_DIFF = "large_diff"
    DB_MIGRATION = "db_migration"
    PROD_ENV = "prod_env"
    NEW_SERVICE = "new_service"
    HOTFIX = "hotfix"


class DeploymentOutcome(StrEnum):
    SUCCESS = "success"
    ROLLBACK = "rollback"
    PARTIAL_FAILURE = "partial_failure"
    FULL_FAILURE = "full_failure"
    DELAYED = "delayed"


# --- Models ---


class DeploymentRiskRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    deployment_id: str = ""
    deployment_type: DeploymentType = DeploymentType.ROLLING
    risk_factor: RiskFactor = RiskFactor.PROD_ENV
    deployment_outcome: DeploymentOutcome = DeploymentOutcome.SUCCESS
    risk_score: float = 0.0
    files_changed: int = 0
    services_affected: int = 0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class DeploymentRiskAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    deployment_type: DeploymentType = DeploymentType.ROLLING
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class DeploymentRiskReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_deployment_type: dict[str, int] = Field(default_factory=dict)
    by_risk_factor: dict[str, int] = Field(default_factory=dict)
    by_deployment_outcome: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class DeploymentRiskScorerEngine:
    """Deployment Risk Scorer Engine — score deployment risk using historical patterns."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = risk_threshold
        self._records: list[DeploymentRiskRecord] = []
        self._analyses: list[DeploymentRiskAnalysis] = []
        logger.info(
            "deployment_risk_scorer_engine.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        deployment_id: str,
        deployment_type: DeploymentType = DeploymentType.ROLLING,
        risk_factor: RiskFactor = RiskFactor.PROD_ENV,
        deployment_outcome: DeploymentOutcome = DeploymentOutcome.SUCCESS,
        risk_score: float = 0.0,
        files_changed: int = 0,
        services_affected: int = 0,
        service: str = "",
        team: str = "",
    ) -> DeploymentRiskRecord:
        record = DeploymentRiskRecord(
            deployment_id=deployment_id,
            deployment_type=deployment_type,
            risk_factor=risk_factor,
            deployment_outcome=deployment_outcome,
            risk_score=risk_score,
            files_changed=files_changed,
            services_affected=services_affected,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "deployment_risk_scorer_engine.record_added",
            record_id=record.id,
            deployment_id=deployment_id,
            deployment_type=deployment_type.value,
            risk_factor=risk_factor.value,
        )
        return record

    def get_record(self, record_id: str) -> DeploymentRiskRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        deployment_type: DeploymentType | None = None,
        risk_factor: RiskFactor | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[DeploymentRiskRecord]:
        results = list(self._records)
        if deployment_type is not None:
            results = [r for r in results if r.deployment_type == deployment_type]
        if risk_factor is not None:
            results = [r for r in results if r.risk_factor == risk_factor]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        deployment_type: DeploymentType = DeploymentType.ROLLING,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> DeploymentRiskAnalysis:
        analysis = DeploymentRiskAnalysis(
            name=name,
            deployment_type=deployment_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "deployment_risk_scorer_engine.analysis_added",
            name=name,
            deployment_type=deployment_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_risk_distribution(self) -> dict[str, Any]:
        factor_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.risk_factor.value
            factor_data.setdefault(key, []).append(r.risk_score)
        result: dict[str, Any] = {}
        for k, scores in factor_data.items():
            result[k] = {
                "count": len(scores),
                "avg_risk_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_high_risk_patterns(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.risk_score >= self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "deployment_id": r.deployment_id,
                        "deployment_type": r.deployment_type.value,
                        "risk_factor": r.risk_factor.value,
                        "deployment_outcome": r.deployment_outcome.value,
                        "risk_score": r.risk_score,
                        "files_changed": r.files_changed,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["risk_score"], reverse=True)

    def detect_deployment_trends(self) -> dict[str, Any]:
        if len(self._analyses) < 2:
            return {"trend": "insufficient_data", "delta": 0.0}
        vals = [a.analysis_score for a in self._analyses]
        mid = len(vals) // 2
        first_half = vals[:mid]
        second_half = vals[mid:]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        delta = round(avg_second - avg_first, 2)
        if abs(delta) < 5.0:
            trend = "stable"
        elif delta > 0:
            trend = "improving"
        else:
            trend = "degrading"
        return {
            "trend": trend,
            "delta": delta,
            "avg_first_half": round(avg_first, 2),
            "avg_second_half": round(avg_second, 2),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> DeploymentRiskReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.deployment_type.value] = by_e1.get(r.deployment_type.value, 0) + 1
            by_e2[r.risk_factor.value] = by_e2.get(r.risk_factor.value, 0) + 1
            by_e3[r.deployment_outcome.value] = by_e3.get(r.deployment_outcome.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.risk_score >= self._threshold)
        scores = [r.risk_score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_high_risk_patterns()
        top_gaps = [g["deployment_id"] for g in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} deployment(s) above risk threshold ({self._threshold})")
        if self._records and avg_score >= self._threshold:
            recs.append(f"Avg risk score {avg_score} at/above threshold ({self._threshold})")
        if not recs:
            recs.append("Deployment Risk Scorer Engine is healthy")
        return DeploymentRiskReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_deployment_type=by_e1,
            by_risk_factor=by_e2,
            by_deployment_outcome=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("deployment_risk_scorer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.deployment_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "risk_threshold": self._threshold,
            "deployment_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
