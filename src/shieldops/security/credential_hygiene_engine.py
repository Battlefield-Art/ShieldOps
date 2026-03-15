"""CredentialHygieneEngine — Track credential security posture."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CredentialType(StrEnum):
    PASSWORD = "password"
    API_KEY = "api_key"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    TOKEN = "token"


class HygieneStatus(StrEnum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    EXPIRED = "expired"


class RotationCompliance(StrEnum):
    ON_SCHEDULE = "on_schedule"
    OVERDUE = "overdue"
    NEVER_ROTATED = "never_rotated"


# --- Models ---


class CredentialHygieneRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    credential_type: CredentialType = CredentialType.PASSWORD
    hygiene_status: HygieneStatus = HygieneStatus.HEALTHY
    rotation_compliance: RotationCompliance = RotationCompliance.ON_SCHEDULE
    score: float = 0.0
    days_since_rotation: int = 0
    mfa_enabled: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CredentialHygieneAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    credential_type: CredentialType = CredentialType.PASSWORD
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CredentialHygieneReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_credential_type: dict[str, int] = Field(default_factory=dict)
    by_hygiene_status: dict[str, int] = Field(default_factory=dict)
    by_rotation_compliance: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CredentialHygieneEngine:
    """Track credential security posture (rotation, strength, MFA, sharing)."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[CredentialHygieneRecord] = []
        self._analyses: list[CredentialHygieneAnalysis] = []
        logger.info(
            "credential_hygiene_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        name: str,
        credential_type: CredentialType = CredentialType.PASSWORD,
        hygiene_status: HygieneStatus = HygieneStatus.HEALTHY,
        rotation_compliance: RotationCompliance = RotationCompliance.ON_SCHEDULE,
        score: float = 0.0,
        days_since_rotation: int = 0,
        mfa_enabled: bool = False,
        service: str = "",
        team: str = "",
    ) -> CredentialHygieneRecord:
        record = CredentialHygieneRecord(
            name=name,
            credential_type=credential_type,
            hygiene_status=hygiene_status,
            rotation_compliance=rotation_compliance,
            score=score,
            days_since_rotation=days_since_rotation,
            mfa_enabled=mfa_enabled,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "credential_hygiene_engine.record_added",
            record_id=record.id,
            name=name,
            credential_type=credential_type.value,
            hygiene_status=hygiene_status.value,
        )
        return record

    def get_record(self, record_id: str) -> CredentialHygieneRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        credential_type: CredentialType | None = None,
        hygiene_status: HygieneStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CredentialHygieneRecord]:
        results = list(self._records)
        if credential_type is not None:
            results = [r for r in results if r.credential_type == credential_type]
        if hygiene_status is not None:
            results = [r for r in results if r.hygiene_status == hygiene_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        credential_type: CredentialType = CredentialType.PASSWORD,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> CredentialHygieneAnalysis:
        analysis = CredentialHygieneAnalysis(
            name=name,
            credential_type=credential_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "credential_hygiene_engine.analysis_added",
            name=name,
            credential_type=credential_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def compute_credential_health(self) -> list[dict[str, Any]]:
        """Compute health score for each credential based on rotation, MFA, and status."""
        results: list[dict[str, Any]] = []
        for r in self._records:
            health_score = r.score
            risk_factors: list[str] = []
            if r.hygiene_status == HygieneStatus.EXPIRED:
                health_score = max(0, health_score - 40)
                risk_factors.append("expired")
            elif r.hygiene_status == HygieneStatus.CRITICAL:
                health_score = max(0, health_score - 25)
                risk_factors.append("critical_status")
            if r.rotation_compliance == RotationCompliance.NEVER_ROTATED:
                health_score = max(0, health_score - 30)
                risk_factors.append("never_rotated")
            elif r.rotation_compliance == RotationCompliance.OVERDUE:
                health_score = max(0, health_score - 15)
                risk_factors.append("overdue_rotation")
            if not r.mfa_enabled:
                health_score = max(0, health_score - 10)
                risk_factors.append("no_mfa")
            results.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "credential_type": r.credential_type.value,
                    "health_score": round(health_score, 2),
                    "risk_factors": risk_factors,
                    "days_since_rotation": r.days_since_rotation,
                }
            )
        return sorted(results, key=lambda x: x["health_score"])

    def identify_expired_credentials(self) -> list[dict[str, Any]]:
        """Identify expired or critically overdue credentials."""
        expired: list[dict[str, Any]] = []
        for r in self._records:
            if r.hygiene_status in (HygieneStatus.EXPIRED, HygieneStatus.CRITICAL):
                expired.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "service": r.service,
                        "credential_type": r.credential_type.value,
                        "hygiene_status": r.hygiene_status.value,
                        "days_since_rotation": r.days_since_rotation,
                        "mfa_enabled": r.mfa_enabled,
                    }
                )
        return sorted(expired, key=lambda x: x["days_since_rotation"], reverse=True)

    def recommend_rotation_schedule(self) -> list[dict[str, Any]]:
        """Recommend rotation schedules based on credential type and risk."""
        rotation_policies = {
            CredentialType.PASSWORD: 90,
            CredentialType.API_KEY: 180,
            CredentialType.SSH_KEY: 365,
            CredentialType.CERTIFICATE: 365,
            CredentialType.TOKEN: 30,
        }
        recommendations: list[dict[str, Any]] = []
        overdue = [
            r for r in self._records if r.rotation_compliance != RotationCompliance.ON_SCHEDULE
        ]
        for r in overdue:
            policy_days = rotation_policies.get(r.credential_type, 90)
            recommendations.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "service": r.service,
                    "credential_type": r.credential_type.value,
                    "days_since_rotation": r.days_since_rotation,
                    "recommended_interval_days": policy_days,
                    "priority": "high" if r.days_since_rotation > policy_days * 2 else "medium",
                    "suggestion": f"Rotate {r.credential_type.value} — "
                    f"{r.days_since_rotation} days since last rotation "
                    f"(policy: {policy_days} days)",
                }
            )
        return sorted(
            recommendations,
            key=lambda x: 0 if x["priority"] == "high" else 1,
        )

    # -- standard methods ---------------------------------------------------

    def analyze_distribution(self) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.credential_type.value
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
                        "credential_type": r.credential_type.value,
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

    def generate_report(self) -> CredentialHygieneReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.credential_type.value] = by_e1.get(r.credential_type.value, 0) + 1
            by_e2[r.hygiene_status.value] = by_e2.get(r.hygiene_status.value, 0) + 1
            by_e3[r.rotation_compliance.value] = by_e3.get(r.rotation_compliance.value, 0) + 1
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
            recs.append("Credential Hygiene Engine is healthy")
        return CredentialHygieneReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_credential_type=by_e1,
            by_hygiene_status=by_e2,
            by_rotation_compliance=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("credential_hygiene_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.credential_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "credential_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
