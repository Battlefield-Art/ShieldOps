"""Secret Rotation Manager Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from .models import (
    HealthVerification,
    RotationAssessment,
    RotationExecution,
    RotationPlan,
    RotationStatus,
    SecretInventory,
    SecretType,
)

logger = structlog.get_logger()

_SECRET_PROFILES: list[dict[str, Any]] = [
    {
        "name": "prod-api-gateway-key",
        "secret_type": SecretType.API_KEY,
        "vault": "aws-secrets-manager",
        "provider": "AWS",
        "owner": "platform-team",
        "age_days": 182,
        "consumers": ["api-gateway", "auth-service"],
    },
    {
        "name": "prod-postgres-password",
        "secret_type": SecretType.DATABASE_CREDENTIAL,
        "vault": "hashicorp-vault",
        "provider": "AWS",
        "owner": "data-team",
        "age_days": 365,
        "consumers": [
            "user-service",
            "order-service",
            "analytics-pipeline",
        ],
    },
    {
        "name": "wildcard-tls-cert",
        "secret_type": SecretType.TLS_CERTIFICATE,
        "vault": "aws-acm",
        "provider": "AWS",
        "owner": "infra-team",
        "age_days": 340,
        "consumers": [
            "ingress-controller",
            "cdn",
            "api-gateway",
        ],
    },
    {
        "name": "deploy-ssh-key",
        "secret_type": SecretType.SSH_KEY,
        "vault": "github-secrets",
        "provider": "GitHub",
        "owner": "devops-team",
        "age_days": 730,
        "consumers": ["ci-pipeline", "deploy-bot"],
    },
    {
        "name": "oauth-client-secret",
        "secret_type": SecretType.OAUTH_TOKEN,
        "vault": "azure-key-vault",
        "provider": "Azure",
        "owner": "identity-team",
        "age_days": 90,
        "consumers": ["sso-gateway"],
    },
    {
        "name": "gcp-sa-key-analytics",
        "secret_type": SecretType.SERVICE_ACCOUNT,
        "vault": "gcp-secret-manager",
        "provider": "GCP",
        "owner": "data-team",
        "age_days": 450,
        "consumers": [
            "bigquery-loader",
            "dataflow-pipeline",
            "looker",
        ],
    },
    {
        "name": "stripe-api-key",
        "secret_type": SecretType.API_KEY,
        "vault": "hashicorp-vault",
        "provider": "Stripe",
        "owner": "payments-team",
        "age_days": 60,
        "consumers": ["billing-service"],
    },
    {
        "name": "k8s-etcd-cert",
        "secret_type": SecretType.TLS_CERTIFICATE,
        "vault": "kubernetes-secrets",
        "provider": "Kubernetes",
        "owner": "infra-team",
        "age_days": 270,
        "consumers": [
            "kube-apiserver",
            "etcd-cluster",
        ],
    },
]

_ROTATION_THRESHOLDS: dict[SecretType, int] = {
    SecretType.API_KEY: 90,
    SecretType.DATABASE_CREDENTIAL: 90,
    SecretType.TLS_CERTIFICATE: 365,
    SecretType.SSH_KEY: 180,
    SecretType.OAUTH_TOKEN: 30,
    SecretType.SERVICE_ACCOUNT: 90,
}


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


def _iso_now() -> str:
    return datetime.now(tz=UTC).isoformat()


def _iso_past(days: int) -> str:
    dt = datetime.now(tz=UTC) - timedelta(
        days=days,
    )
    return dt.isoformat()


class SecretRotationManagerToolkit:
    """Tools for automated secret rotation."""

    def __init__(
        self,
        vault_client: Any | None = None,
        cloud_provider: Any | None = None,
    ) -> None:
        self._vault_client = vault_client
        self._cloud_provider = cloud_provider

    async def inventory_secrets(
        self,
        tenant_id: str,
    ) -> list[SecretInventory]:
        """Discover and inventory secrets across vaults."""
        logger.info(
            "srm.inventory_secrets",
            tenant_id=tenant_id,
        )

        if self._vault_client is not None:
            try:
                raw = await self._vault_client.list_secrets(
                    tenant_id=tenant_id,
                )
                return [SecretInventory(**r) for r in raw]
            except Exception:
                logger.exception("srm.inventory.error")

        secrets: list[SecretInventory] = []
        for i, p in enumerate(_SECRET_PROFILES):
            noise = random.randint(-10, 10)  # noqa: S311
            age = max(1, p["age_days"] + noise)
            secrets.append(
                SecretInventory(
                    id=_gen_id("SEC", tenant_id, i),
                    name=p["name"],
                    secret_type=p["secret_type"],
                    vault=p["vault"],
                    provider=p["provider"],
                    owner=p["owner"],
                    age_days=age,
                    last_rotated=_iso_past(age),
                    consumers=p["consumers"],
                    tags={"env": "production"},
                )
            )
        return secrets

    async def assess_rotation(
        self,
        secrets: list[SecretInventory],
    ) -> list[RotationAssessment]:
        """Assess which secrets need rotation."""
        logger.info(
            "srm.assess_rotation",
            count=len(secrets),
        )

        assessments: list[RotationAssessment] = []
        for s in secrets:
            threshold = _ROTATION_THRESHOLDS.get(
                s.secret_type,
                90,
            )
            overdue_ratio = s.age_days / max(threshold, 1)
            risk = min(round(overdue_ratio * 40, 1), 100.0)
            compliant = s.age_days <= threshold

            if overdue_ratio > 2.0:
                urgency = "critical"
            elif overdue_ratio > 1.0:
                urgency = "high"
            elif overdue_ratio > 0.8:
                urgency = "medium"
            else:
                urgency = "low"

            consumers = len(s.consumers)
            if consumers >= 3:
                blast = "high"
            elif consumers >= 2:
                blast = "medium"
            else:
                blast = "low"

            assessments.append(
                RotationAssessment(
                    secret_id=s.id,
                    secret_name=s.name,
                    secret_type=s.secret_type,
                    risk_score=risk,
                    age_days=s.age_days,
                    policy_compliant=compliant,
                    rotation_urgency=urgency,
                    consumer_count=consumers,
                    blast_radius=blast,
                )
            )
        return assessments

    async def plan_rotation(
        self,
        assessments: list[RotationAssessment],
    ) -> list[RotationPlan]:
        """Generate rotation plans for non-compliant secrets."""
        logger.info(
            "srm.plan_rotation",
            count=len(assessments),
        )

        plans: list[RotationPlan] = []
        idx = 0
        for a in assessments:
            if a.policy_compliant and a.rotation_urgency == "low":
                continue

            if a.secret_type == SecretType.DATABASE_CREDENTIAL:
                strategy = "dual-write"
                steps = [
                    "Create new credential in vault",
                    "Add new credential to connection pool",
                    "Drain connections using old credential",
                    "Verify all connections use new credential",
                    "Revoke old credential",
                ]
            elif a.secret_type == SecretType.TLS_CERTIFICATE:
                strategy = "blue-green"
                steps = [
                    "Generate new certificate via CA",
                    "Deploy cert to staging listeners",
                    "Validate TLS handshake on staging",
                    "Switch production listeners to new cert",
                    "Revoke old certificate",
                ]
            else:
                strategy = "rolling-update"
                steps = [
                    "Generate new secret value",
                    "Store new version in vault",
                    "Update consumers via rolling deploy",
                    "Verify consumer health",
                    "Delete old secret version",
                ]

            plans.append(
                RotationPlan(
                    id=_gen_id("RP", a.secret_id, idx),
                    secret_id=a.secret_id,
                    secret_name=a.secret_name,
                    strategy=strategy,
                    pre_checks=[
                        "Verify vault connectivity",
                        "Check consumer health baseline",
                        "Confirm rollback path",
                    ],
                    steps=steps,
                    rollback_steps=[
                        "Restore previous secret version",
                        "Restart affected consumers",
                        "Verify rollback health",
                    ],
                    estimated_downtime_seconds=0,
                    requires_approval=(a.blast_radius == "high"),
                )
            )
            idx += 1
        return plans

    async def execute_rotation(
        self,
        plans: list[RotationPlan],
    ) -> list[RotationExecution]:
        """Execute rotation plans."""
        logger.info(
            "srm.execute_rotation",
            count=len(plans),
        )

        results: list[RotationExecution] = []
        for i, p in enumerate(plans):
            if p.requires_approval:
                results.append(
                    RotationExecution(
                        id=_gen_id("RE", p.id, i),
                        plan_id=p.id,
                        secret_id=p.secret_id,
                        status=RotationStatus.PENDING,
                        started_at=_iso_now(),
                        new_secret_version="",
                        rollback_available=True,
                    )
                )
            else:
                success = random.random() > 0.1  # noqa: S311
                results.append(
                    RotationExecution(
                        id=_gen_id("RE", p.id, i),
                        plan_id=p.id,
                        secret_id=p.secret_id,
                        status=(RotationStatus.COMPLETED if success else RotationStatus.FAILED),
                        started_at=_iso_now(),
                        completed_at=_iso_now(),
                        new_secret_version=(
                            f"v{random.randint(2, 99)}"  # noqa: S311
                            if success
                            else ""
                        ),
                        rollback_available=True,
                        error_message=("" if success else "Vault write timeout"),
                    )
                )
        return results

    async def verify_health(
        self,
        executions: list[RotationExecution],
        secrets: list[SecretInventory],
    ) -> list[HealthVerification]:
        """Verify consumer health after rotation."""
        logger.info(
            "srm.verify_health",
            count=len(executions),
        )

        secret_map = {s.id: s for s in secrets}
        checks: list[HealthVerification] = []

        for ex in executions:
            if ex.status != RotationStatus.COMPLETED:
                continue
            secret = secret_map.get(ex.secret_id)
            consumers = secret.consumers if secret else ["unknown"]
            for svc in consumers:
                healthy = random.random() > 0.05  # noqa: S311
                checks.append(
                    HealthVerification(
                        execution_id=ex.id,
                        secret_id=ex.secret_id,
                        service_name=svc,
                        healthy=healthy,
                        latency_ms=round(
                            random.uniform(5, 200),  # noqa: S311
                            1,
                        ),
                        error_rate_pct=round(
                            0.0 if healthy else random.uniform(1, 15),  # noqa: S311
                            2,
                        ),
                        verified_at=_iso_now(),
                    )
                )
        return checks
