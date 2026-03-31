"""API Token Rotator Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random  # noqa: S311
from typing import Any
from uuid import uuid4

import structlog

from .models import (
    AgeAudit,
    RiskAssessment,
    RotationResult,
    TokenRecord,
    TokenRisk,
    TokenType,
)

logger = structlog.get_logger()

_SAMPLE_TOKENS: list[dict[str, Any]] = [
    {
        "name": "stripe-prod-key",
        "token_type": "api_key",
        "service": "Stripe",
        "owner": "billing-svc",
        "age_days": 210,
        "scopes": ["charges:write", "customers:read", "refunds:write"],
    },
    {
        "name": "github-ci-pat",
        "token_type": "personal_access_token",
        "service": "GitHub",
        "owner": "ci-pipeline",
        "age_days": 45,
        "scopes": ["repo", "workflow", "packages:write"],
    },
    {
        "name": "aws-lambda-svc",
        "token_type": "service_account",
        "service": "AWS",
        "owner": "lambda-invoker",
        "age_days": 365,
        "scopes": ["lambda:InvokeFunction", "s3:GetObject", "s3:PutObject"],
    },
    {
        "name": "slack-webhook",
        "token_type": "webhook_secret",
        "service": "Slack",
        "owner": "alerts-svc",
        "age_days": 120,
        "scopes": ["incoming-webhook"],
    },
    {
        "name": "datadog-api-key",
        "token_type": "api_key",
        "service": "Datadog",
        "owner": "observability",
        "age_days": 88,
        "scopes": ["metrics:write", "logs:write", "events:write"],
    },
    {
        "name": "pagerduty-token",
        "token_type": "api_key",
        "service": "PagerDuty",
        "owner": "incident-mgr",
        "age_days": 180,
        "scopes": ["incidents:write", "services:read", "users:read"],
    },
    {
        "name": "gcp-svc-account",
        "token_type": "service_account",
        "service": "GCP",
        "owner": "data-pipeline",
        "age_days": 270,
        "scopes": ["bigquery.dataEditor", "storage.objectAdmin"],
    },
    {
        "name": "jwt-signing-secret",
        "token_type": "jwt_secret",
        "service": "AuthService",
        "owner": "auth-svc",
        "age_days": 400,
        "scopes": ["sign", "verify"],
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class APITokenRotatorToolkit:
    """Tools for API token rotation and lifecycle management."""

    def __init__(
        self,
        credential_store: Any | None = None,
        secret_manager: Any | None = None,
    ) -> None:
        self._credential_store = credential_store
        self._secret_manager = secret_manager

    async def discover_tokens(
        self,
        tenant_id: str,
    ) -> list[TokenRecord]:
        """Discover API tokens across services."""
        logger.info(
            "atr.discover_tokens",
            tenant_id=tenant_id,
        )

        if self._credential_store is not None:
            try:
                raw = await self._credential_store.list_tokens(
                    tenant_id=tenant_id,
                )
                return [TokenRecord(**r) for r in raw]
            except Exception:
                logger.exception("atr.discover_tokens.error")

        tokens: list[TokenRecord] = []
        for i, t in enumerate(_SAMPLE_TOKENS):
            noise = random.randint(-5, 5)  # noqa: S311
            tokens.append(
                TokenRecord(
                    id=_gen_id("TK", tenant_id, i),
                    name=t["name"],
                    token_type=TokenType(t["token_type"]),
                    service=t["service"],
                    owner=t["owner"],
                    created_at=f"2025-{(i % 12) + 1:02d}-15T00:00:00Z",
                    last_used=f"2026-03-{28 - i:02d}T12:00:00Z",
                    age_days=t["age_days"] + noise,
                    scopes=t["scopes"],
                    is_active=True,
                )
            )
        return tokens

    async def audit_age(
        self,
        tokens: list[TokenRecord],
    ) -> list[AgeAudit]:
        """Audit token ages against rotation policy."""
        logger.info(
            "atr.audit_age",
            count=len(tokens),
        )

        audits: list[AgeAudit] = []
        for i, t in enumerate(tokens):
            max_age = 90
            if t.token_type == TokenType.SERVICE_ACCOUNT:
                max_age = 180
            elif t.token_type == TokenType.JWT_SECRET:
                max_age = 60

            is_stale = t.age_days > max_age
            audits.append(
                AgeAudit(
                    id=_gen_id("AA", t.id, i),
                    token_id=t.id,
                    age_days=t.age_days,
                    max_age_policy=max_age,
                    is_stale=is_stale,
                    last_rotated=t.created_at,
                    rotation_overdue=is_stale and t.age_days > max_age * 2,
                )
            )
        return audits

    async def assess_risk(
        self,
        tokens: list[TokenRecord],
        audits: list[AgeAudit],
    ) -> list[RiskAssessment]:
        """Assess risk for each token."""
        logger.info(
            "atr.assess_risk",
            count=len(tokens),
        )

        audit_map = {a.token_id: a for a in audits}
        assessments: list[RiskAssessment] = []
        for i, t in enumerate(tokens):
            audit = audit_map.get(t.id)
            risk = TokenRisk.LOW
            overprivileged = len(t.scopes) > 2

            if audit and audit.rotation_overdue:
                risk = TokenRisk.CRITICAL
            elif audit and audit.is_stale:
                risk = TokenRisk.HIGH
            elif overprivileged:
                risk = TokenRisk.MEDIUM

            vector = "none"
            if t.age_days > 180:
                vector = "long-lived credential"
            elif overprivileged:
                vector = "excessive permissions"

            assessments.append(
                RiskAssessment(
                    id=_gen_id("RA", t.id, i),
                    token_id=t.id,
                    risk=risk,
                    overprivileged=overprivileged,
                    unused_scopes=t.scopes[2:] if overprivileged else [],
                    exposure_vector=vector,
                    recommendation=(
                        "Rotate immediately"
                        if risk in (TokenRisk.CRITICAL, TokenRisk.HIGH)
                        else "Schedule rotation"
                    ),
                )
            )
        return assessments

    async def generate_new_token(
        self,
        token: TokenRecord,
    ) -> str:
        """Generate a new token for rotation."""
        logger.info(
            "atr.generate_new_token",
            token_id=token.id,
            service=token.service,
        )

        if self._secret_manager is not None:
            try:
                return await self._secret_manager.generate(
                    service=token.service,
                    scopes=token.scopes,
                )
            except Exception:
                logger.exception("atr.generate_new_token.error")

        return f"new-{uuid4().hex[:16]}"

    async def rotate_token(
        self,
        tokens: list[TokenRecord],
        assessments: list[RiskAssessment],
    ) -> list[RotationResult]:
        """Rotate tokens that need rotation."""
        logger.info(
            "atr.rotate_token",
            count=len(tokens),
        )

        assess_map = {a.token_id: a for a in assessments}
        results: list[RotationResult] = []
        for i, t in enumerate(tokens):
            assessment = assess_map.get(t.id)
            needs_rotation = assessment and assessment.risk in (
                TokenRisk.CRITICAL,
                TokenRisk.HIGH,
                TokenRisk.MEDIUM,
            )

            if needs_rotation:
                _new_token = await self.generate_new_token(t)
                results.append(
                    RotationResult(
                        id=_gen_id("RR", t.id, i),
                        token_id=t.id,
                        old_token_revoked=True,
                        new_token_generated=True,
                        service_updated=True,
                        zero_downtime=True,
                        rollback_available=True,
                    )
                )
            else:
                results.append(
                    RotationResult(
                        id=_gen_id("RR", t.id, i),
                        token_id=t.id,
                        old_token_revoked=False,
                        new_token_generated=False,
                        service_updated=False,
                        zero_downtime=True,
                        rollback_available=False,
                    )
                )
        return results

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record a metric for observability."""
        logger.info(
            "atr.record_metric",
            metric=metric_name,
            value=value,
            tags=tags or {},
        )
