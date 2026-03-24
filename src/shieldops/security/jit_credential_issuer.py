"""JIT Credential Issuer — just-in-time credential provisioning for AI agents."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CredentialScope(StrEnum):
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    ADMIN = "admin"
    CUSTOM = "custom"


class CredentialStatus(StrEnum):
    ISSUED = "issued"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    DENIED = "denied"


class CredentialProvider(StrEnum):
    AWS_STS = "aws_sts"
    GCP_IAM = "gcp_iam"
    AZURE_AD = "azure_ad"
    VAULT = "vault"
    INTERNAL = "internal"


# --- Models ---


class JITCredentialRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    scope: CredentialScope = CredentialScope.READ_ONLY
    provider: CredentialProvider = CredentialProvider.INTERNAL
    status: CredentialStatus = CredentialStatus.ISSUED
    ttl_seconds: int = 3600
    issued_at: float = Field(default_factory=time.time)
    expires_at: float = 0.0
    revoked_at: float | None = None
    usage_count: int = 0
    max_usage: int = 0
    reason: str = ""


class JITPolicy(BaseModel):
    agent_id: str = ""
    max_scope: CredentialScope = CredentialScope.READ_WRITE
    max_ttl_seconds: int = 7200
    max_concurrent: int = 5
    allowed_providers: list[str] = Field(default_factory=list)
    require_justification: bool = False


class JITCredentialReport(BaseModel):
    total_issued: int = 0
    active_count: int = 0
    revoked_count: int = 0
    expired_count: int = 0
    denied_count: int = 0
    by_scope: dict[str, int] = Field(default_factory=dict)
    by_provider: dict[str, int] = Field(default_factory=dict)
    over_privileged: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


_SCOPE_ORDER: list[CredentialScope] = [
    CredentialScope.READ_ONLY,
    CredentialScope.READ_WRITE,
    CredentialScope.ADMIN,
    CredentialScope.CUSTOM,
]


# --- Engine ---


class JITCredentialIssuer:
    """Just-in-time credential provisioning for AI agents."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[JITCredentialRecord] = []
        self._policies: dict[str, JITPolicy] = {}
        logger.info("jit_credential_issuer.initialized", max_records=max_records)

    def request_credential(
        self,
        agent_id: str,
        scope: CredentialScope = CredentialScope.READ_ONLY,
        provider: CredentialProvider = CredentialProvider.INTERNAL,
        ttl_seconds: int = 3600,
        reason: str = "",
    ) -> JITCredentialRecord:
        policy = self._policies.get(agent_id)
        if policy:
            scope_idx = _SCOPE_ORDER.index(scope) if scope in _SCOPE_ORDER else 0
            max_idx = (
                _SCOPE_ORDER.index(policy.max_scope) if policy.max_scope in _SCOPE_ORDER else 0
            )
            if scope_idx > max_idx:
                record = JITCredentialRecord(
                    agent_id=agent_id,
                    scope=scope,
                    provider=provider,
                    status=CredentialStatus.DENIED,
                    ttl_seconds=ttl_seconds,
                    reason=f"scope {scope.value} exceeds policy max {policy.max_scope.value}",
                )
                self._records.append(record)
                if len(self._records) > self._max_records:
                    self._records = self._records[-self._max_records :]
                return record
            if ttl_seconds > policy.max_ttl_seconds:
                ttl_seconds = policy.max_ttl_seconds
        now = time.time()
        record = JITCredentialRecord(
            agent_id=agent_id,
            scope=scope,
            provider=provider,
            status=CredentialStatus.ISSUED,
            ttl_seconds=ttl_seconds,
            issued_at=now,
            expires_at=now + ttl_seconds,
            reason=reason,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        return record

    def revoke_credential(self, credential_id: str) -> JITCredentialRecord | None:
        for r in self._records:
            if r.id == credential_id and r.status in (
                CredentialStatus.ISSUED,
                CredentialStatus.ACTIVE,
            ):
                r.status = CredentialStatus.REVOKED
                r.revoked_at = time.time()
                return r
        return None

    def rotate_credential(self, credential_id: str) -> dict[str, Any]:
        old = None
        for r in self._records:
            if r.id == credential_id:
                old = r
                break
        if old is None:
            return {"status": "not_found"}
        self.revoke_credential(credential_id)
        new = self.request_credential(
            agent_id=old.agent_id,
            scope=old.scope,
            provider=old.provider,
            ttl_seconds=old.ttl_seconds,
            reason=f"rotation of {credential_id}",
        )
        return {"old_id": credential_id, "new_id": new.id, "status": "rotated"}

    def set_policy(self, agent_id: str, policy: JITPolicy) -> None:
        self._policies[agent_id] = policy

    def enforce_policy(self, agent_id: str, requested_scope: CredentialScope) -> dict[str, Any]:
        policy = self._policies.get(agent_id)
        if not policy:
            return {"allowed": True, "reason": "no_policy_configured"}
        scope_idx = _SCOPE_ORDER.index(requested_scope) if requested_scope in _SCOPE_ORDER else 0
        max_idx = _SCOPE_ORDER.index(policy.max_scope) if policy.max_scope in _SCOPE_ORDER else 0
        if scope_idx > max_idx:
            return {
                "allowed": False,
                "reason": f"scope {requested_scope.value} exceeds max {policy.max_scope.value}",
            }
        return {"allowed": True, "reason": "within_policy"}

    def detect_over_privileged(self, min_usage_ratio: float = 0.1) -> list[JITCredentialRecord]:
        results: list[JITCredentialRecord] = []
        for r in self._records:
            if r.status not in (CredentialStatus.ISSUED, CredentialStatus.ACTIVE):
                continue
            if r.scope in (CredentialScope.ADMIN, CredentialScope.READ_WRITE) and (
                r.max_usage > 0
                and r.usage_count / r.max_usage < min_usage_ratio
                or r.usage_count == 0
            ):
                results.append(r)
        return results

    def expire_stale(self) -> list[JITCredentialRecord]:
        now = time.time()
        expired: list[JITCredentialRecord] = []
        for r in self._records:
            if (
                r.status in (CredentialStatus.ISSUED, CredentialStatus.ACTIVE)
                and r.expires_at > 0
                and now >= r.expires_at
            ):
                r.status = CredentialStatus.EXPIRED
                expired.append(r)
        return expired

    def generate_report(self) -> JITCredentialReport:
        by_scope: dict[str, int] = {}
        by_provider: dict[str, int] = {}
        for r in self._records:
            by_scope[r.scope.value] = by_scope.get(r.scope.value, 0) + 1
            by_provider[r.provider.value] = by_provider.get(r.provider.value, 0) + 1
        active = sum(
            1
            for r in self._records
            if r.status in (CredentialStatus.ISSUED, CredentialStatus.ACTIVE)
        )
        revoked = sum(1 for r in self._records if r.status == CredentialStatus.REVOKED)
        expired = sum(1 for r in self._records if r.status == CredentialStatus.EXPIRED)
        denied = sum(1 for r in self._records if r.status == CredentialStatus.DENIED)
        over_priv = len(self.detect_over_privileged())
        recs: list[str] = []
        if over_priv > 0:
            recs.append(f"{over_priv} over-privileged credentials detected")
        if denied > 0:
            recs.append(f"{denied} credential requests denied by policy")
        if not recs:
            recs.append("JIT credential posture is healthy")
        return JITCredentialReport(
            total_issued=len(self._records),
            active_count=active,
            revoked_count=revoked,
            expired_count=expired,
            denied_count=denied,
            by_scope=by_scope,
            by_provider=by_provider,
            over_privileged=over_priv,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        status_dist: dict[str, int] = {}
        for r in self._records:
            status_dist[r.status.value] = status_dist.get(r.status.value, 0) + 1
        return {
            "total_records": len(self._records),
            "total_policies": len(self._policies),
            "status_distribution": status_dist,
            "unique_agents": len({r.agent_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._policies.clear()
        return {"status": "cleared"}
