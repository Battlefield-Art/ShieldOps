"""Agent Session Revoker — bulk credential and session revocation."""

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
    OAUTH_TOKEN = "oauth_token"  # noqa: S105
    API_KEY = "api_key"
    JWT_SESSION = "jwt_session"
    MCP_CONNECTION = "mcp_connection"
    SERVICE_ACCOUNT = "service_account"
    TEMP_CREDENTIAL = "temp_credential"


class RevocationScope(StrEnum):
    SINGLE_CREDENTIAL = "single_credential"
    AGENT_ALL = "agent_all"
    ENVIRONMENT_ALL = "environment_all"
    GLOBAL_EMERGENCY = "global_emergency"


class RevocationStatus(StrEnum):
    PENDING = "pending"
    REVOKED = "revoked"
    FAILED = "failed"
    EXPIRED = "expired"
    NOT_FOUND = "not_found"


# --- Models ---


class RevocationRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    credential_type: CredentialType = CredentialType.API_KEY
    credential_id: str = ""
    scope: RevocationScope = RevocationScope.SINGLE_CREDENTIAL
    status: RevocationStatus = RevocationStatus.PENDING
    revoked_at: float = Field(default_factory=time.time)
    error_message: str = ""


class RevocationPolicy(BaseModel):
    agent_id: str = ""
    auto_revoke_on_trip: bool = True
    credential_types_to_revoke: list[str] = Field(default_factory=list)
    notify_dependent_services: bool = True


class RevocationReport(BaseModel):
    total_revocations: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_agent: dict[str, int] = Field(default_factory=dict)
    failed_revocations: int = 0
    avg_revocation_time_ms: float = 0.0
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AgentSessionRevoker:
    """Bulk revocation of credentials and sessions for AI agents."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._records: list[RevocationRecord] = []
        self._policies: dict[str, RevocationPolicy] = {}
        self._revocation_times: dict[str, float] = {}
        logger.info("agent_session_revoker.initialized", max_records=max_records)

    # -- core operations -------------------------------------------------

    def revoke(
        self,
        agent_id: str,
        credential_type: CredentialType = CredentialType.API_KEY,
        credential_id: str = "",
    ) -> RevocationRecord:
        """Revoke a single credential for an agent."""
        start = time.time()
        record = RevocationRecord(
            agent_id=agent_id,
            credential_type=credential_type,
            credential_id=credential_id or str(uuid.uuid4()),
            scope=RevocationScope.SINGLE_CREDENTIAL,
            status=RevocationStatus.REVOKED,
        )
        elapsed_ms = round((time.time() - start) * 1000, 2)
        self._revocation_times[record.id] = elapsed_ms
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_session_revoker.revoked",
            record_id=record.id,
            agent_id=agent_id,
            credential_type=credential_type.value,
        )
        return record

    def revoke_all(self, agent_id: str) -> list[RevocationRecord]:
        """Bulk revoke all credentials for an agent."""
        policy = self._policies.get(agent_id)
        types_to_revoke: list[CredentialType]
        if policy and policy.credential_types_to_revoke:
            types_to_revoke = [
                CredentialType(t)
                for t in policy.credential_types_to_revoke
                if t in [ct.value for ct in CredentialType]
            ]
        else:
            types_to_revoke = list(CredentialType)
        results: list[RevocationRecord] = []
        for ctype in types_to_revoke:
            record = RevocationRecord(
                agent_id=agent_id,
                credential_type=ctype,
                credential_id=f"{agent_id}_{ctype.value}_{uuid.uuid4().hex[:8]}",
                scope=RevocationScope.AGENT_ALL,
                status=RevocationStatus.REVOKED,
            )
            results.append(record)
            self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "agent_session_revoker.revoked_all",
            agent_id=agent_id,
            count=len(results),
        )
        return results

    def set_policy(self, agent_id: str, policy: RevocationPolicy) -> None:
        """Configure auto-revocation policy for an agent."""
        self._policies[agent_id] = policy
        logger.info("agent_session_revoker.policy_set", agent_id=agent_id)

    def check_revocation_status(self, revocation_id: str) -> RevocationRecord | None:
        """Check status of a specific revocation."""
        for r in self._records:
            if r.id == revocation_id:
                return r
        return None

    # -- domain operations -----------------------------------------------

    def detect_lingering_sessions(self, agent_id: str) -> list[dict[str, Any]]:
        """Detect sessions still active after revocation."""
        revoked = [
            r
            for r in self._records
            if r.agent_id == agent_id and r.status == RevocationStatus.REVOKED
        ]
        failed = [
            r
            for r in self._records
            if r.agent_id == agent_id and r.status == RevocationStatus.FAILED
        ]
        lingering: list[dict[str, Any]] = []
        for f in failed:
            lingering.append(
                {
                    "credential_id": f.credential_id,
                    "credential_type": f.credential_type.value,
                    "status": f.status.value,
                    "error": f.error_message,
                }
            )
        revoked_types = {r.credential_type for r in revoked}
        all_types = set(CredentialType)
        missing = all_types - revoked_types
        for ctype in missing:
            lingering.append(
                {
                    "credential_type": ctype.value,
                    "status": "potentially_active",
                    "error": "no revocation record found",
                }
            )
        return lingering

    def get_agent_revocation_history(self, agent_id: str) -> list[RevocationRecord]:
        """Get full revocation history for an agent."""
        return [r for r in self._records if r.agent_id == agent_id]

    def count_by_scope(self) -> dict[str, int]:
        """Count revocations grouped by scope."""
        counts: dict[str, int] = {}
        for r in self._records:
            counts[r.scope.value] = counts.get(r.scope.value, 0) + 1
        return counts

    # -- report / stats --------------------------------------------------

    def generate_revocation_report(self) -> RevocationReport:
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_agent: dict[str, int] = {}
        for r in self._records:
            by_type[r.credential_type.value] = by_type.get(r.credential_type.value, 0) + 1
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
            by_agent[r.agent_id] = by_agent.get(r.agent_id, 0) + 1
        failed = sum(1 for r in self._records if r.status == RevocationStatus.FAILED)
        times = list(self._revocation_times.values())
        avg_time = round(sum(times) / len(times), 2) if times else 0.0
        return RevocationReport(
            total_revocations=len(self._records),
            by_type=by_type,
            by_status=by_status,
            by_agent=by_agent,
            failed_revocations=failed,
            avg_revocation_time_ms=avg_time,
        )

    def get_stats(self) -> dict[str, Any]:
        status_dist: dict[str, int] = {}
        for r in self._records:
            status_dist[r.status.value] = status_dist.get(r.status.value, 0) + 1
        return {
            "total_revocations": len(self._records),
            "total_policies": len(self._policies),
            "status_distribution": status_dist,
            "unique_agents": len({r.agent_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._policies.clear()
        self._revocation_times.clear()
        logger.info("agent_session_revoker.cleared")
        return {"status": "cleared"}
