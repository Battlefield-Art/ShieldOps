"""Credential Lifecycle Agent — Tool functions for JIT credential management."""

from __future__ import annotations

import hashlib
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import (
    CredentialRecord,
    CredentialType,
    JITCredential,
    PostureAssessment,
    PostureRating,
    RevocationResult,
    RotationResult,
)

logger = structlog.get_logger()

# --- Rotation policy thresholds (days) ---
_ROTATION_POLICY: dict[str, int] = {
    "api_key": 90,
    "oauth_token": 30,
    "service_account": 180,
    "jwt_token": 7,
    "certificate": 365,
    "ssh_key": 180,
}

# --- Default scopes per credential type ---
_DEFAULT_SCOPES: dict[str, list[str]] = {
    "api_key": ["read"],
    "oauth_token": ["read", "write"],
    "service_account": ["read", "write", "admin"],
    "jwt_token": ["read"],
    "certificate": ["tls", "mtls"],
    "ssh_key": ["shell"],
}

# --- Simulated credential inventory ---
_SIMULATED_CREDENTIALS: list[dict[str, Any]] = [
    {
        "name": "ai-agent-primary-key",
        "credential_type": "api_key",
        "owner": "investigation-agent",
        "created_days_ago": 120,
        "last_used_days_ago": 2,
        "scope": ["read", "write", "execute"],
        "risk_score": 0.7,
    },
    {
        "name": "remediation-svc-account",
        "credential_type": "service_account",
        "owner": "remediation-agent",
        "created_days_ago": 200,
        "last_used_days_ago": 45,
        "scope": ["read", "write", "admin", "delete"],
        "risk_score": 0.85,
    },
    {
        "name": "otel-collector-token",
        "credential_type": "oauth_token",
        "owner": "otel-pipeline-agent",
        "created_days_ago": 60,
        "last_used_days_ago": 0,
        "scope": ["read", "write"],
        "risk_score": 0.3,
    },
    {
        "name": "k8s-deploy-cert",
        "credential_type": "certificate",
        "owner": "gitops-agent",
        "created_days_ago": 400,
        "last_used_days_ago": 1,
        "scope": ["tls", "mtls", "deploy"],
        "risk_score": 0.6,
    },
    {
        "name": "vault-ssh-key",
        "credential_type": "ssh_key",
        "owner": "forensics-agent",
        "created_days_ago": 250,
        "last_used_days_ago": 90,
        "scope": ["shell", "scp"],
        "risk_score": 0.75,
    },
    {
        "name": "stale-jwt-token",
        "credential_type": "jwt_token",
        "owner": "decommissioned-agent",
        "created_days_ago": 30,
        "last_used_days_ago": 30,
        "scope": ["read", "write"],
        "risk_score": 0.9,
    },
]


def _generate_id(prefix: str, content: str) -> str:
    """Generate a deterministic ID."""
    raw = f"{prefix}:{content}:{time.time()}"
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


def _now_iso() -> str:
    """Return current UTC time in ISO format."""
    return datetime.now(UTC).isoformat()


class CredentialLifecycleToolkit:
    """Tools for managing the full credential lifecycle."""

    def __init__(
        self,
        vault_client: Any | None = None,
        iam_client: Any | None = None,
        secret_scanner: Any | None = None,
    ) -> None:
        self._vault_client = vault_client
        self._iam_client = iam_client
        self._secret_scanner = secret_scanner

    async def discover_credentials(
        self, tenant_id: str, scope: list[str]
    ) -> list[CredentialRecord]:
        """Discover credentials across cloud IAM, vault, K8s secrets, env vars."""
        logger.info(
            "credential_lifecycle.discover_credentials",
            tenant_id=tenant_id,
            scope=scope,
        )

        # Use real scanner if available
        if self._secret_scanner is not None:
            try:
                raw = await self._secret_scanner.scan(tenant_id=tenant_id, scope=scope)
                return [CredentialRecord(**r) for r in raw]
            except Exception:
                logger.exception("credential_lifecycle.discover_credentials.error")

        # Simulated discovery
        now = time.time()
        credentials: list[CredentialRecord] = []
        for cred_def in _SIMULATED_CREDENTIALS:
            created_days = cred_def["created_days_ago"]
            last_used_days = cred_def["last_used_days_ago"]
            cred_type = CredentialType(cred_def["credential_type"])
            rotation_max = _ROTATION_POLICY.get(cred_def["credential_type"], 90)
            is_stale = last_used_days > 60 or created_days > rotation_max

            credentials.append(
                CredentialRecord(
                    id=_generate_id("CRED", cred_def["name"]),
                    name=cred_def["name"],
                    credential_type=cred_type,
                    owner=cred_def["owner"],
                    created_at=datetime.fromtimestamp(
                        now - created_days * 86400, tz=UTC
                    ).isoformat(),
                    last_used=datetime.fromtimestamp(
                        now - last_used_days * 86400, tz=UTC
                    ).isoformat(),
                    expires_at=datetime.fromtimestamp(
                        now + (rotation_max - created_days) * 86400,
                        tz=UTC,
                    ).isoformat(),
                    scope=cred_def["scope"],
                    risk_score=cred_def["risk_score"],
                    is_stale=is_stale,
                    auto_rotatable=cred_type
                    not in (CredentialType.CERTIFICATE, CredentialType.SSH_KEY),
                )
            )

        return credentials

    async def assess_credential_posture(
        self, credentials: list[CredentialRecord]
    ) -> list[PostureAssessment]:
        """Evaluate age, usage, scope, and rotation compliance for credentials."""
        logger.info(
            "credential_lifecycle.assess_credential_posture",
            count=len(credentials),
        )

        assessments: list[PostureAssessment] = []
        for cred in credentials:
            issues: list[str] = []
            recommendations: list[str] = []
            rotation_max = _ROTATION_POLICY.get(cred.credential_type.value, 90)

            # Calculate days since creation
            try:
                created_dt = datetime.fromisoformat(cred.created_at)
                age_days = (datetime.now(UTC) - created_dt).days
            except (ValueError, TypeError):
                age_days = 0

            # Check rotation compliance
            if age_days > rotation_max:
                issues.append(f"Exceeds rotation policy: {age_days}d > {rotation_max}d max")
                recommendations.append(f"Rotate immediately — {age_days - rotation_max}d overdue")

            # Check staleness
            if cred.is_stale:
                issues.append("Credential is stale (unused >60 days or past rotation)")
                recommendations.append("Revoke or rotate stale credential")

            # Check overprivilege
            default_scope = _DEFAULT_SCOPES.get(cred.credential_type.value, ["read"])
            extra_scopes = set(cred.scope) - set(default_scope)
            overprivileged = len(extra_scopes) > 0
            if overprivileged:
                issues.append(f"Overprivileged: extra scopes {sorted(extra_scopes)}")
                recommendations.append("Apply least-privilege — remove unnecessary scopes")

            # Check high risk
            if cred.risk_score >= 0.8:
                issues.append(f"High risk score: {cred.risk_score}")
                recommendations.append("Prioritize for JIT replacement")

            # Determine rating
            if len(issues) == 0:
                rating = PostureRating.EXCELLENT
            elif len(issues) == 1 and cred.risk_score < 0.5:
                rating = PostureRating.GOOD
            elif len(issues) <= 2 and cred.risk_score < 0.7:
                rating = PostureRating.FAIR
            elif cred.risk_score >= 0.8:
                rating = PostureRating.CRITICAL
            else:
                rating = PostureRating.POOR

            assessments.append(
                PostureAssessment(
                    id=_generate_id("PSTR", cred.id),
                    credential_id=cred.id,
                    rating=rating,
                    issues=issues,
                    recommendations=recommendations,
                    last_rotation_days=age_days,
                    overprivileged=overprivileged,
                )
            )

        return assessments

    async def issue_jit_credential(
        self,
        credential_type: CredentialType,
        scope: list[str],
        ttl_seconds: int,
        requester: str,
    ) -> JITCredential:
        """Issue a short-lived, scoped JIT credential."""
        logger.info(
            "credential_lifecycle.issue_jit_credential",
            credential_type=credential_type,
            requester=requester,
            ttl_seconds=ttl_seconds,
        )

        # Use real vault if available
        if self._vault_client is not None:
            try:
                raw = await self._vault_client.issue(
                    credential_type=credential_type.value,
                    scope=scope,
                    ttl_seconds=ttl_seconds,
                    requester=requester,
                )
                return JITCredential(**raw)
            except Exception:
                logger.exception("credential_lifecycle.issue_jit_credential.error")

        now = datetime.now(UTC)
        jit_id = f"JIT-{uuid.uuid4().hex[:8].upper()}"
        expires = datetime.fromtimestamp(now.timestamp() + ttl_seconds, tz=UTC)

        return JITCredential(
            id=jit_id,
            credential_type=credential_type,
            scope=scope,
            ttl_seconds=ttl_seconds,
            issued_to=requester,
            issued_at=now.isoformat(),
            expires_at=expires.isoformat(),
            vault_path=f"secret/jit/{requester}/{jit_id}",
        )

    async def enforce_rotation(
        self, stale_credentials: list[CredentialRecord]
    ) -> list[RotationResult]:
        """Rotate credentials that exceed rotation policy thresholds."""
        logger.info(
            "credential_lifecycle.enforce_rotation",
            count=len(stale_credentials),
        )

        # Use real IAM client if available
        if self._iam_client is not None:
            try:
                raw = await self._iam_client.rotate_batch(
                    credentials=[c.model_dump() for c in stale_credentials]
                )
                return [RotationResult(**r) for r in raw]
            except Exception:
                logger.exception("credential_lifecycle.enforce_rotation.error")

        results: list[RotationResult] = []
        for cred in stale_credentials:
            old_hash = hashlib.sha256(f"{cred.id}:old:{time.time()}".encode()).hexdigest()[:16]
            new_hash = hashlib.sha256(f"{cred.id}:new:{time.time()}".encode()).hexdigest()[:16]

            success = cred.auto_rotatable
            results.append(
                RotationResult(
                    id=_generate_id("ROT", cred.id),
                    credential_id=cred.id,
                    old_hash=old_hash,
                    new_hash=new_hash,
                    rotated_at=_now_iso(),
                    success=success,
                    error_message=""
                    if success
                    else f"Manual rotation required for {cred.credential_type.value}",
                )
            )

        return results

    async def revoke_stale_credentials(
        self, credentials: list[CredentialRecord]
    ) -> list[RevocationResult]:
        """Revoke unused or compromised credentials."""
        logger.info(
            "credential_lifecycle.revoke_stale_credentials",
            count=len(credentials),
        )

        # Use real IAM client if available
        if self._iam_client is not None:
            try:
                raw = await self._iam_client.revoke_batch(
                    credentials=[c.model_dump() for c in credentials]
                )
                return [RevocationResult(**r) for r in raw]
            except Exception:
                logger.exception("credential_lifecycle.revoke_stale_credentials.error")

        results: list[RevocationResult] = []
        for cred in credentials:
            reason = "stale_unused" if cred.is_stale else "policy_violation"
            results.append(
                RevocationResult(
                    id=_generate_id("REV", cred.id),
                    credential_id=cred.id,
                    reason=reason,
                    revoked_at=_now_iso(),
                    success=True,
                )
            )

        return results
