"""JIT Credential Issuer Engine — track just-in-time credential issuance for AI agents."""

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
    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"
    SERVICE_ACCOUNT = "service_account"
    JWT = "jwt"
    CERTIFICATE = "certificate"
    SSH_KEY = "ssh_key"


class IssuanceReason(StrEnum):
    SCHEDULED_TASK = "scheduled_task"
    ON_DEMAND = "on_demand"
    ROTATION = "rotation"
    EMERGENCY = "emergency"
    ESCALATION = "escalation"


class CredentialStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"
    PENDING = "pending"


# --- Models ---


class IssuanceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    credential_type: CredentialType = CredentialType.API_KEY
    issuance_reason: IssuanceReason = IssuanceReason.ON_DEMAND
    credential_status: CredentialStatus = CredentialStatus.PENDING
    requester: str = ""
    scope: str = ""
    ttl_seconds: int = 0
    issued_at: float = Field(default_factory=time.time)
    expires_at: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class IssuanceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    credential_type: CredentialType = CredentialType.API_KEY
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class IssuanceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    active_count: int = 0
    expired_count: int = 0
    avg_ttl_seconds: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_reason: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    top_requesters: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class JITCredentialIssuerEngine:
    """Track just-in-time credential issuance and lifecycle for AI agents."""

    def __init__(
        self,
        max_records: int = 200000,
        max_ttl_threshold: float = 3600.0,
    ) -> None:
        self._max_records = max_records
        self._max_ttl_threshold = max_ttl_threshold
        self._records: list[IssuanceRecord] = []
        self._analyses: list[IssuanceAnalysis] = []
        logger.info(
            "jit_credential_issuer_engine.initialized",
            max_records=max_records,
            max_ttl_threshold=max_ttl_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        credential_type: CredentialType = CredentialType.API_KEY,
        issuance_reason: IssuanceReason = IssuanceReason.ON_DEMAND,
        credential_status: CredentialStatus = CredentialStatus.PENDING,
        requester: str = "",
        scope: str = "",
        ttl_seconds: int = 0,
        service: str = "",
        team: str = "",
    ) -> IssuanceRecord:
        now = time.time()
        record = IssuanceRecord(
            credential_type=credential_type,
            issuance_reason=issuance_reason,
            credential_status=credential_status,
            requester=requester,
            scope=scope,
            ttl_seconds=ttl_seconds,
            issued_at=now,
            expires_at=now + ttl_seconds if ttl_seconds > 0 else 0.0,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "jit_credential_issuer_engine.record_added",
            record_id=record.id,
            credential_type=credential_type.value,
            issuance_reason=issuance_reason.value,
            ttl_seconds=ttl_seconds,
        )
        return record

    def get_record(self, record_id: str) -> IssuanceRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        credential_type: CredentialType | None = None,
        issuance_reason: IssuanceReason | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[IssuanceRecord]:
        results = list(self._records)
        if credential_type is not None:
            results = [r for r in results if r.credential_type == credential_type]
        if issuance_reason is not None:
            results = [r for r in results if r.issuance_reason == issuance_reason]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        credential_type: CredentialType = CredentialType.API_KEY,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> IssuanceAnalysis:
        analysis = IssuanceAnalysis(
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
            "jit_credential_issuer_engine.analysis_added",
            credential_type=credential_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_issuance_patterns(self) -> dict[str, Any]:
        """Analyze credential issuance patterns by type and reason."""
        type_data: dict[str, list[int]] = {}
        for r in self._records:
            key = r.credential_type.value
            type_data.setdefault(key, []).append(r.ttl_seconds)
        result: dict[str, Any] = {}
        for k, ttls in type_data.items():
            result[k] = {
                "count": len(ttls),
                "avg_ttl_seconds": round(sum(ttls) / len(ttls), 2),
            }
        return result

    def identify_long_lived_credentials(self) -> list[dict[str, Any]]:
        """Identify credentials with TTLs exceeding the threshold."""
        long_lived: list[dict[str, Any]] = []
        for r in self._records:
            if r.ttl_seconds > self._max_ttl_threshold:
                long_lived.append(
                    {
                        "record_id": r.id,
                        "credential_type": r.credential_type.value,
                        "issuance_reason": r.issuance_reason.value,
                        "credential_status": r.credential_status.value,
                        "requester": r.requester,
                        "ttl_seconds": r.ttl_seconds,
                        "scope": r.scope,
                        "service": r.service,
                    }
                )
        return sorted(long_lived, key=lambda x: x["ttl_seconds"], reverse=True)

    def detect_issuance_trends(self) -> list[dict[str, Any]]:
        """Detect trends in credential issuance by requester."""
        requester_data: dict[str, list[IssuanceRecord]] = {}
        for r in self._records:
            requester_data.setdefault(r.requester, []).append(r)
        trends: list[dict[str, Any]] = []
        for req, records in requester_data.items():
            emergency_count = sum(
                1 for r in records if r.issuance_reason == IssuanceReason.EMERGENCY
            )
            ttls = [r.ttl_seconds for r in records]
            avg_ttl = round(sum(ttls) / len(ttls), 2) if ttls else 0.0
            trends.append(
                {
                    "requester": req,
                    "total_issuances": len(records),
                    "emergency_count": emergency_count,
                    "avg_ttl_seconds": avg_ttl,
                    "trend": ("concerning" if emergency_count > len(records) * 0.3 else "normal"),
                }
            )
        return sorted(trends, key=lambda x: x["total_issuances"], reverse=True)

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.requester == key or r.service == key]
        if not matched:
            return {"key": key, "status": "not_found", "count": 0}
        ttls = [r.ttl_seconds for r in matched]
        avg_ttl = round(sum(ttls) / len(ttls), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_ttl_seconds": avg_ttl,
            "above_threshold": sum(1 for t in ttls if t > self._max_ttl_threshold),
        }

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> IssuanceReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.credential_type.value] = by_e1.get(r.credential_type.value, 0) + 1
            by_e2[r.issuance_reason.value] = by_e2.get(r.issuance_reason.value, 0) + 1
            by_e3[r.credential_status.value] = by_e3.get(r.credential_status.value, 0) + 1
        active_count = sum(
            1 for r in self._records if r.credential_status == CredentialStatus.ACTIVE
        )
        expired_count = sum(
            1 for r in self._records if r.credential_status == CredentialStatus.EXPIRED
        )
        ttls = [r.ttl_seconds for r in self._records]
        avg_ttl = round(sum(ttls) / len(ttls), 2) if ttls else 0.0
        requester_counts: dict[str, int] = {}
        for r in self._records:
            requester_counts[r.requester] = requester_counts.get(r.requester, 0) + 1
        top_requesters = sorted(
            requester_counts,
            key=lambda k: requester_counts.get(k, 0),
            reverse=True,
        )[:5]
        recs: list[str] = []
        long_lived = self.identify_long_lived_credentials()
        if long_lived:
            recs.append(
                f"{len(long_lived)} credential(s) exceed max TTL threshold "
                f"({self._max_ttl_threshold}s)"
            )
        if self._records and expired_count > 0:
            recs.append(f"{expired_count} expired credential(s) need cleanup")
        if not recs:
            recs.append("JIT Credential Issuer Engine is healthy")
        return IssuanceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            active_count=active_count,
            expired_count=expired_count,
            avg_ttl_seconds=avg_ttl,
            by_type=by_e1,
            by_reason=by_e2,
            by_status=by_e3,
            top_requesters=top_requesters,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("jit_credential_issuer_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.credential_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "max_ttl_threshold": self._max_ttl_threshold,
            "credential_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
