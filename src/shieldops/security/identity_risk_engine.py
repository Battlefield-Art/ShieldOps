"""Identity Risk Engine —
score identity and access risks, detect anomalous access patterns,
and recommend access changes for zero-trust enforcement."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class IdentityRiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AccessPattern(StrEnum):
    NORMAL = "normal"
    ANOMALOUS = "anomalous"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class IdentityType(StrEnum):
    USER = "user"
    SERVICE = "service"
    API_KEY = "api_key"
    MACHINE = "machine"


# --- Models ---


class IdentityRiskRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    identity_id: str = ""
    identity_name: str = ""
    identity_risk_level: IdentityRiskLevel = IdentityRiskLevel.LOW
    access_pattern: AccessPattern = AccessPattern.NORMAL
    identity_type: IdentityType = IdentityType.USER
    risk_score: float = 0.0
    login_location: str = ""
    privileges_used: int = 0
    privileges_granted: int = 0
    failed_auth_count: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IdentityRiskAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    identity_id: str = ""
    identity_risk_level: IdentityRiskLevel = IdentityRiskLevel.LOW
    access_pattern: AccessPattern = AccessPattern.NORMAL
    composite_score: float = 0.0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IdentityRiskReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    avg_risk_score: float = 0.0
    by_identity_risk_level: dict[str, int] = Field(default_factory=dict)
    by_access_pattern: dict[str, int] = Field(default_factory=dict)
    by_identity_type: dict[str, int] = Field(default_factory=dict)
    high_risk_identities: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class IdentityRiskEngine:
    """Score identity and access risks, detect anomalous access patterns,
    and recommend access changes for zero-trust enforcement."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[IdentityRiskRecord] = []
        self._analyses: dict[str, IdentityRiskAnalysis] = {}
        logger.info(
            "identity_risk_engine.init",
            max_records=max_records,
        )

    def add_record(
        self,
        identity_id: str = "",
        identity_name: str = "",
        identity_risk_level: IdentityRiskLevel = IdentityRiskLevel.LOW,
        access_pattern: AccessPattern = AccessPattern.NORMAL,
        identity_type: IdentityType = IdentityType.USER,
        risk_score: float = 0.0,
        login_location: str = "",
        privileges_used: int = 0,
        privileges_granted: int = 0,
        failed_auth_count: int = 0,
        description: str = "",
    ) -> IdentityRiskRecord:
        record = IdentityRiskRecord(
            identity_id=identity_id,
            identity_name=identity_name,
            identity_risk_level=identity_risk_level,
            access_pattern=access_pattern,
            identity_type=identity_type,
            risk_score=risk_score,
            login_location=login_location,
            privileges_used=privileges_used,
            privileges_granted=privileges_granted,
            failed_auth_count=failed_auth_count,
            description=description,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "identity_risk.record_added",
            record_id=record.id,
            identity_id=identity_id,
        )
        return record

    def process(self, key: str) -> IdentityRiskAnalysis | dict[str, Any]:
        rec = None
        for r in self._records:
            if r.id == key:
                rec = r
                break
        if rec is None:
            return {"status": "not_found", "key": key}
        pattern_weight = {
            AccessPattern.NORMAL: 0.0,
            AccessPattern.ANOMALOUS: 0.3,
            AccessPattern.IMPOSSIBLE_TRAVEL: 0.6,
            AccessPattern.PRIVILEGE_ESCALATION: 0.8,
        }
        composite = round(
            rec.risk_score * 0.6 + pattern_weight.get(rec.access_pattern, 0.0) * 0.4,
            4,
        )
        if composite >= 0.8:
            level = IdentityRiskLevel.CRITICAL
        elif composite >= 0.6:
            level = IdentityRiskLevel.HIGH
        elif composite >= 0.3:
            level = IdentityRiskLevel.MEDIUM
        else:
            level = IdentityRiskLevel.LOW
        analysis = IdentityRiskAnalysis(
            identity_id=rec.identity_id,
            identity_risk_level=level,
            access_pattern=rec.access_pattern,
            composite_score=composite,
            description=(f"Identity {rec.identity_id} -> risk={level.value} composite={composite}"),
        )
        self._analyses[key] = analysis
        return analysis

    def generate_report(self) -> IdentityRiskReport:
        by_level: dict[str, int] = {}
        by_pattern: dict[str, int] = {}
        by_type: dict[str, int] = {}
        scores: list[float] = []
        for r in self._records:
            by_level[r.identity_risk_level.value] = by_level.get(r.identity_risk_level.value, 0) + 1
            by_pattern[r.access_pattern.value] = by_pattern.get(r.access_pattern.value, 0) + 1
            by_type[r.identity_type.value] = by_type.get(r.identity_type.value, 0) + 1
            scores.append(r.risk_score)
        avg_score = round(sum(scores) / len(scores), 4) if scores else 0.0
        high_risk = list(
            {
                r.identity_id
                for r in self._records
                if r.identity_risk_level in (IdentityRiskLevel.CRITICAL, IdentityRiskLevel.HIGH)
                and r.identity_id
            }
        )[:10]
        recs: list[str] = []
        if high_risk:
            recs.append(f"{len(high_risk)} identities have critical/high risk levels")
        if avg_score > 0.6:
            recs.append("Average risk score is elevated above 0.6")
        if not recs:
            recs.append("Identity risk engine operating within normal parameters")
        return IdentityRiskReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            avg_risk_score=avg_score,
            by_identity_risk_level=by_level,
            by_access_pattern=by_pattern,
            by_identity_type=by_type,
            high_risk_identities=high_risk,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        level_dist: dict[str, int] = {}
        for r in self._records:
            level_dist[r.identity_risk_level.value] = (
                level_dist.get(r.identity_risk_level.value, 0) + 1
            )
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "identity_risk_level_distribution": level_dist,
        }

    def clear_data(self) -> dict[str, str]:
        self._records = []
        self._analyses = {}
        logger.info("identity_risk_engine.cleared")
        return {"status": "cleared"}

    # --- domain methods ---

    def score_identity_risk(self, identity_id: str = "") -> dict[str, Any]:
        """Compute composite risk score for a specific identity."""
        identity_records = [r for r in self._records if r.identity_id == identity_id]
        if not identity_records:
            return {
                "identity_id": identity_id,
                "composite_score": 0.0,
                "risk_level": "no_data",
                "event_count": 0,
            }
        avg_score = sum(r.risk_score for r in identity_records) / len(identity_records)
        max_score = max(r.risk_score for r in identity_records)
        composite = round(avg_score * 0.4 + max_score * 0.6, 4)
        patterns = list({r.access_pattern.value for r in identity_records})
        identity_types = list({r.identity_type.value for r in identity_records})
        if composite >= 0.8:
            level = IdentityRiskLevel.CRITICAL.value
        elif composite >= 0.6:
            level = IdentityRiskLevel.HIGH.value
        elif composite >= 0.3:
            level = IdentityRiskLevel.MEDIUM.value
        else:
            level = IdentityRiskLevel.LOW.value
        return {
            "identity_id": identity_id,
            "composite_score": composite,
            "risk_level": level,
            "avg_score": round(avg_score, 4),
            "max_score": max_score,
            "event_count": len(identity_records),
            "access_patterns": patterns,
            "identity_types": identity_types,
        }

    def detect_anomalous_access(self) -> list[dict[str, Any]]:
        """Detect identities with anomalous access patterns."""
        identity_data: dict[str, list[IdentityRiskRecord]] = {}
        for r in self._records:
            if r.identity_id:
                identity_data.setdefault(r.identity_id, []).append(r)
        results: list[dict[str, Any]] = []
        for identity_id, recs in identity_data.items():
            anomalous = [r for r in recs if r.access_pattern != AccessPattern.NORMAL]
            if not anomalous:
                continue
            anomaly_rate = round(len(anomalous) / len(recs), 4)
            patterns = list({r.access_pattern.value for r in anomalous})
            avg_risk = round(sum(r.risk_score for r in anomalous) / len(anomalous), 4)
            total_failed_auth = sum(r.failed_auth_count for r in anomalous)
            locations = list({r.login_location for r in anomalous if r.login_location})
            results.append(
                {
                    "identity_id": identity_id,
                    "anomaly_rate": anomaly_rate,
                    "anomalous_patterns": patterns,
                    "avg_risk_score": avg_risk,
                    "total_failed_auth": total_failed_auth,
                    "unique_locations": locations[:5],
                    "anomalous_event_count": len(anomalous),
                    "severity": (
                        "critical"
                        if anomaly_rate >= 0.7
                        else "high"
                        if anomaly_rate >= 0.4
                        else "medium"
                    ),
                }
            )
        results.sort(key=lambda x: x["anomaly_rate"], reverse=True)
        return results

    def recommend_access_changes(self) -> list[dict[str, Any]]:
        """Recommend access changes based on privilege usage patterns."""
        identity_data: dict[str, list[IdentityRiskRecord]] = {}
        for r in self._records:
            if r.identity_id and r.privileges_granted > 0:
                identity_data.setdefault(r.identity_id, []).append(r)
        results: list[dict[str, Any]] = []
        for identity_id, recs in identity_data.items():
            max_granted = max(r.privileges_granted for r in recs)
            max_used = max(r.privileges_used for r in recs)
            usage_ratio = round(max_used / max_granted, 4) if max_granted else 0.0
            avg_risk = round(sum(r.risk_score for r in recs) / len(recs), 4)
            identity_types = list({r.identity_type.value for r in recs})
            changes: list[str] = []
            if usage_ratio < 0.3:
                changes.append("Revoke unused privileges — least-privilege enforcement")
            if avg_risk > 0.7:
                changes.append("Require MFA for all access")
            if any(r.access_pattern == AccessPattern.PRIVILEGE_ESCALATION for r in recs):
                changes.append("Investigate privilege escalation events")
            if any(r.access_pattern == AccessPattern.IMPOSSIBLE_TRAVEL for r in recs):
                changes.append("Enable geo-based access restrictions")
            if not changes:
                changes.append("Access patterns within acceptable range")
            results.append(
                {
                    "identity_id": identity_id,
                    "usage_ratio": usage_ratio,
                    "privileges_granted": max_granted,
                    "privileges_used": max_used,
                    "avg_risk_score": avg_risk,
                    "identity_types": identity_types,
                    "recommended_changes": changes,
                    "record_count": len(recs),
                }
            )
        results.sort(key=lambda x: x["usage_ratio"])
        return results
