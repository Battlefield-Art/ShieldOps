"""CredentialHygieneEngine — Audit credential posture."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CredentialAge(StrEnum):
    FRESH = "fresh"
    CURRENT = "current"
    AGING = "aging"
    STALE = "stale"
    EXPIRED = "expired"


class PolicyCompliance(StrEnum):
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    EXEMPT = "exempt"
    UNKNOWN = "unknown"


class RotationStatus(StrEnum):
    ON_SCHEDULE = "on_schedule"
    DUE_SOON = "due_soon"
    OVERDUE = "overdue"
    NEVER_ROTATED = "never_rotated"
    MANUAL = "manual"


# --- Models ---


class CredentialHygieneRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    age: CredentialAge = CredentialAge.CURRENT
    compliance: PolicyCompliance = PolicyCompliance.COMPLIANT
    rotation: RotationStatus = RotationStatus.ON_SCHEDULE
    score: float = 0.0
    days_since_rotation: int = 0
    mfa_enabled: bool = False
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class CredentialHygieneAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    age: CredentialAge = CredentialAge.CURRENT
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
    by_age: dict[str, int] = Field(default_factory=dict)
    by_compliance: dict[str, int] = Field(default_factory=dict)
    by_rotation: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class CredentialHygieneEngine:
    """Audit credential hygiene and rotation."""

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

    def add_record(
        self,
        name: str,
        age: CredentialAge = CredentialAge.CURRENT,
        compliance: PolicyCompliance = (PolicyCompliance.COMPLIANT),
        rotation: RotationStatus = (RotationStatus.ON_SCHEDULE),
        score: float = 0.0,
        days_since_rotation: int = 0,
        mfa_enabled: bool = False,
        service: str = "",
        team: str = "",
    ) -> CredentialHygieneRecord:
        record = CredentialHygieneRecord(
            name=name,
            age=age,
            compliance=compliance,
            rotation=rotation,
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
            age=age.value,
        )
        return record

    def get_record(self, record_id: str) -> CredentialHygieneRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        age: CredentialAge | None = None,
        compliance: PolicyCompliance | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[CredentialHygieneRecord]:
        results = list(self._records)
        if age is not None:
            results = [r for r in results if r.age == age]
        if compliance is not None:
            results = [r for r in results if r.compliance == compliance]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    # -- domain operations --------------------------------

    def audit_credential(self, name: str) -> dict[str, Any]:
        """Audit a specific credential."""
        matched = [r for r in self._records if r.name == name]
        if not matched:
            return {
                "name": name,
                "status": "not_found",
            }
        latest = matched[-1]
        risk_factors: list[str] = []
        if latest.age in (
            CredentialAge.STALE,
            CredentialAge.EXPIRED,
        ):
            risk_factors.append("aging_credential")
        if latest.rotation in (
            RotationStatus.OVERDUE,
            RotationStatus.NEVER_ROTATED,
        ):
            risk_factors.append("rotation_overdue")
        if not latest.mfa_enabled:
            risk_factors.append("no_mfa")
        return {
            "name": name,
            "age": latest.age.value,
            "compliance": latest.compliance.value,
            "rotation": latest.rotation.value,
            "score": latest.score,
            "risk_factors": risk_factors,
        }

    def check_rotation_compliance(
        self,
    ) -> list[dict[str, Any]]:
        """Check rotation compliance for all creds."""
        results: list[dict[str, Any]] = []
        overdue = [
            r
            for r in self._records
            if r.rotation
            in (
                RotationStatus.OVERDUE,
                RotationStatus.NEVER_ROTATED,
            )
        ]
        for r in overdue:
            results.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "rotation": r.rotation.value,
                    "days_since_rotation": (r.days_since_rotation),
                    "service": r.service,
                    "team": r.team,
                    "priority": (
                        "critical"
                        if r.days_since_rotation > 365
                        else "high"
                        if r.days_since_rotation > 180
                        else "medium"
                    ),
                }
            )
        return sorted(
            results,
            key=lambda x: x["days_since_rotation"],
            reverse=True,
        )

    def calculate_hygiene_score(
        self,
    ) -> dict[str, Any]:
        """Calculate overall hygiene score."""
        if not self._records:
            return {"hygiene_score": 0.0}
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2)
        compliant = sum(1 for r in self._records if r.compliance == PolicyCompliance.COMPLIANT)
        with_mfa = sum(1 for r in self._records if r.mfa_enabled)
        total = len(self._records)
        return {
            "hygiene_score": avg,
            "total_credentials": total,
            "compliance_rate": round(compliant / total, 3),
            "mfa_rate": round(with_mfa / total, 3),
            "stale_count": sum(
                1
                for r in self._records
                if r.age
                in (
                    CredentialAge.STALE,
                    CredentialAge.EXPIRED,
                )
            ),
        }

    # -- standard methods ---------------------------------

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

    def generate_report(
        self,
    ) -> CredentialHygieneReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.age.value] = by_e1.get(r.age.value, 0) + 1
            by_e2[r.compliance.value] = by_e2.get(r.compliance.value, 0) + 1
            by_e3[r.rotation.value] = by_e3.get(r.rotation.value, 0) + 1
        scores = [r.score for r in self._records]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_ct = sum(1 for r in self._records if r.score < self._threshold)
        gap_list = [r.name for r in self._records if r.score < self._threshold][:5]
        recs: list[str] = []
        if gap_ct > 0:
            recs.append(f"{gap_ct} credential(s) below threshold ({self._threshold})")
        if self._records and avg < self._threshold:
            recs.append(f"Avg score {avg} below threshold ({self._threshold})")
        if not recs:
            recs.append("Credential hygiene engine healthy")
        return CredentialHygieneReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_ct,
            avg_score=avg,
            by_age=by_e1,
            by_compliance=by_e2,
            by_rotation=by_e3,
            top_gaps=gap_list,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        age_dist: dict[str, int] = {}
        for r in self._records:
            k = r.age.value
            age_dist[k] = age_dist.get(k, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "age_distribution": age_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("credential_hygiene_engine.cleared")
        return {"status": "cleared"}
