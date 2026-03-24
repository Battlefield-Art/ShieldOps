"""AI Credential Manager — manage and secure credentials for AI/LLM providers."""

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
    OAUTH_TOKEN = "oauth_token"  # noqa: S105
    SERVICE_ACCOUNT = "service_account"
    JWT_TOKEN = "jwt_token"  # noqa: S105
    CERTIFICATE = "certificate"
    TEMP_CREDENTIAL = "temp_credential"


class CredentialScope(StrEnum):
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    ADMIN = "admin"
    RESTRICTED = "restricted"
    CUSTOM = "custom"


class CredentialStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    COMPROMISED = "compromised"
    ROTATING = "rotating"


# --- Models ---


class AICredentialRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    credential_type: CredentialType = CredentialType.API_KEY
    scope: CredentialScope = CredentialScope.READ_ONLY
    status: CredentialStatus = CredentialStatus.ACTIVE
    provider: str = ""
    app_id: str = ""
    owner: str = ""
    expires_at: float = 0.0
    last_rotated: float = 0.0
    rotation_count: int = 0
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CredentialPolicy(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    max_scope: CredentialScope = CredentialScope.READ_WRITE
    max_lifetime_hours: int = 720
    require_rotation: bool = True
    rotation_interval_hours: int = 168
    allowed_types: list[CredentialType] = Field(default_factory=list)
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class CredentialReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_credentials: int = 0
    total_policies: int = 0
    active_count: int = 0
    expired_count: int = 0
    compromised_count: int = 0
    avg_rotation_age_hours: float = 0.0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_scope: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    over_privileged: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AICredentialManager:
    """Manage and secure credentials for AI/LLM provider integrations."""

    def __init__(
        self,
        max_records: int = 200000,
        default_rotation_hours: int = 168,
    ) -> None:
        self._max_records = max_records
        self._default_rotation_hours = default_rotation_hours
        self._credentials: list[AICredentialRecord] = []
        self._policies: list[CredentialPolicy] = []
        logger.info(
            "ai_credential_manager.initialized",
            max_records=max_records,
            default_rotation_hours=default_rotation_hours,
        )

    # -- registration / query --------------------------------------------------

    def register_credential(
        self,
        name: str,
        credential_type: CredentialType = CredentialType.API_KEY,
        scope: CredentialScope = CredentialScope.READ_ONLY,
        status: CredentialStatus = CredentialStatus.ACTIVE,
        provider: str = "",
        app_id: str = "",
        owner: str = "",
        expires_at: float = 0.0,
        description: str = "",
    ) -> AICredentialRecord:
        credential = AICredentialRecord(
            name=name,
            credential_type=credential_type,
            scope=scope,
            status=status,
            provider=provider,
            app_id=app_id,
            owner=owner,
            expires_at=expires_at,
            last_rotated=time.time(),
            description=description,
        )
        self._credentials.append(credential)
        if len(self._credentials) > self._max_records:
            self._credentials = self._credentials[-self._max_records :]
        logger.info(
            "ai_credential_manager.credential_registered",
            credential_id=credential.id,
            name=name,
            credential_type=credential_type.value,
            scope=scope.value,
        )
        return credential

    # -- domain operations -----------------------------------------------------

    def rotate_credential(self, credential_id: str) -> dict[str, Any]:
        """Rotate a credential and update its status."""
        cred = next((c for c in self._credentials if c.id == credential_id), None)
        if cred is None:
            return {"error": "credential_not_found", "credential_id": credential_id}

        old_status = cred.status.value
        cred.status = CredentialStatus.ROTATING
        cred.last_rotated = time.time()
        cred.rotation_count += 1

        # After rotation, mark as active
        cred.status = CredentialStatus.ACTIVE
        logger.info(
            "ai_credential_manager.credential_rotated",
            credential_id=credential_id,
            old_status=old_status,
            rotation_count=cred.rotation_count,
        )
        return {
            "credential_id": credential_id,
            "name": cred.name,
            "status": cred.status.value,
            "rotation_count": cred.rotation_count,
            "rotated_at": cred.last_rotated,
        }

    def revoke_credential(self, credential_id: str, reason: str = "") -> dict[str, Any]:
        """Revoke a credential immediately."""
        cred = next((c for c in self._credentials if c.id == credential_id), None)
        if cred is None:
            return {"error": "credential_not_found", "credential_id": credential_id}

        cred.status = CredentialStatus.REVOKED
        logger.info(
            "ai_credential_manager.credential_revoked",
            credential_id=credential_id,
            reason=reason,
        )
        return {
            "credential_id": credential_id,
            "name": cred.name,
            "status": CredentialStatus.REVOKED.value,
            "reason": reason,
        }

    def enforce_least_privilege(self) -> list[dict[str, Any]]:
        """Check credentials against policies and enforce least-privilege."""
        violations: list[dict[str, Any]] = []
        scope_order = list(CredentialScope)

        for cred in self._credentials:
            if cred.status != CredentialStatus.ACTIVE:
                continue
            for policy in self._policies:
                max_idx = scope_order.index(policy.max_scope)
                cred_idx = scope_order.index(cred.scope)
                if cred_idx > max_idx:
                    violations.append(
                        {
                            "credential_id": cred.id,
                            "name": cred.name,
                            "current_scope": cred.scope.value,
                            "max_allowed_scope": policy.max_scope.value,
                            "policy": policy.name,
                            "action": "downgrade_scope",
                        }
                    )
        return violations

    def detect_over_privileged(self) -> list[dict[str, Any]]:
        """Detect credentials with excessive permissions."""
        results: list[dict[str, Any]] = []
        now = time.time()
        for cred in self._credentials:
            if cred.status != CredentialStatus.ACTIVE:
                continue
            issues: list[str] = []
            if cred.scope == CredentialScope.ADMIN:
                issues.append("admin_scope")
            if cred.expires_at > 0 and cred.expires_at < now:
                issues.append("expired_but_active")
            rotation_age_h = (now - cred.last_rotated) / 3600 if cred.last_rotated > 0 else 0
            if rotation_age_h > self._default_rotation_hours:
                issues.append("rotation_overdue")
            if issues:
                results.append(
                    {
                        "credential_id": cred.id,
                        "name": cred.name,
                        "scope": cred.scope.value,
                        "provider": cred.provider,
                        "issues": issues,
                        "issue_count": len(issues),
                        "risk": "high" if len(issues) >= 2 else "medium",
                    }
                )
        return results

    # -- report / stats --------------------------------------------------------

    def generate_report(self) -> CredentialReport:
        by_type: dict[str, int] = {}
        by_scope: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for c in self._credentials:
            by_type[c.credential_type.value] = by_type.get(c.credential_type.value, 0) + 1
            by_scope[c.scope.value] = by_scope.get(c.scope.value, 0) + 1
            by_status[c.status.value] = by_status.get(c.status.value, 0) + 1

        active = sum(1 for c in self._credentials if c.status == CredentialStatus.ACTIVE)
        expired = sum(1 for c in self._credentials if c.status == CredentialStatus.EXPIRED)
        compromised = sum(1 for c in self._credentials if c.status == CredentialStatus.COMPROMISED)

        now = time.time()
        rotation_ages: list[float] = []
        for c in self._credentials:
            if c.last_rotated > 0:
                rotation_ages.append((now - c.last_rotated) / 3600)
        avg_rotation_age = (
            round(sum(rotation_ages) / len(rotation_ages), 1) if rotation_ages else 0.0
        )

        over_priv = self.detect_over_privileged()
        over_priv_names = [o["name"] for o in over_priv[:5]]

        recs: list[str] = []
        if compromised > 0:
            recs.append(f"{compromised} compromised credential(s) — revoke and rotate immediately")
        if expired > 0:
            recs.append(f"{expired} expired credential(s) — clean up or renew")
        overdue = [o for o in over_priv if "rotation_overdue" in o.get("issues", [])]
        if overdue:
            recs.append(f"{len(overdue)} credential(s) overdue for rotation")
        if not recs:
            recs.append("AI credential posture is healthy")

        return CredentialReport(
            total_credentials=len(self._credentials),
            total_policies=len(self._policies),
            active_count=active,
            expired_count=expired,
            compromised_count=compromised,
            avg_rotation_age_hours=avg_rotation_age,
            by_type=by_type,
            by_scope=by_scope,
            by_status=by_status,
            over_privileged=over_priv_names,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        type_dist: dict[str, int] = {}
        for c in self._credentials:
            key = c.credential_type.value
            type_dist[key] = type_dist.get(key, 0) + 1
        return {
            "total_credentials": len(self._credentials),
            "total_policies": len(self._policies),
            "default_rotation_hours": self._default_rotation_hours,
            "type_distribution": type_dist,
            "unique_providers": len({c.provider for c in self._credentials}),
            "unique_apps": len({c.app_id for c in self._credentials}),
        }

    def clear_data(self) -> dict[str, str]:
        self._credentials.clear()
        self._policies.clear()
        logger.info("ai_credential_manager.cleared")
        return {"status": "cleared"}
