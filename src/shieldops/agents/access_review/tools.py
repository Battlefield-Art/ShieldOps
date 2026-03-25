"""Tool functions for the Access Review Agent.

These bridge IAM providers, directory services, and entitlement systems
to the agent's LangGraph nodes.
"""

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.connectors.base import ConnectorRouter

logger = structlog.get_logger()


class AccessReviewToolkit:
    """Collection of tools for access review campaigns."""

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        repository: Any = None,
    ) -> None:
        self._router = connector_router
        self._repository = repository

    async def collect_entitlements(
        self,
        tenant_id: str,
        identity_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Collect all entitlements for identities in a tenant.

        Queries IAM providers (AWS IAM, Azure AD, GCP IAM, K8s RBAC)
        and returns normalized entitlement records.
        """
        identity_types = identity_types or [
            "human",
            "service_account",
            "ai_agent",
        ]
        logger.info(
            "access_review.collecting_entitlements",
            tenant_id=tenant_id,
            types=identity_types,
        )

        if self._router is None:
            return self._mock_entitlements(tenant_id, identity_types)

        entitlements: list[dict[str, Any]] = []
        for provider_name in ("aws", "azure", "gcp", "kubernetes"):
            try:
                connector = self._router.get(provider_name)
                provider_entitlements = await connector.list_entitlements(
                    tenant_id=tenant_id,
                    identity_types=identity_types,
                )
                entitlements.extend(provider_entitlements)
            except (ValueError, AttributeError, Exception) as exc:
                logger.warning(
                    "access_review.provider_collection_failed",
                    provider=provider_name,
                    error=str(exc),
                )
        return entitlements

    async def check_last_usage(
        self,
        entitlement_ids: list[str],
    ) -> dict[str, float]:
        """Check last usage timestamp for a batch of entitlements.

        Returns mapping of entitlement_id -> last_used_epoch.
        A value of 0.0 means never used.
        """
        logger.info(
            "access_review.checking_usage",
            count=len(entitlement_ids),
        )

        if self._router is None:
            now = time.time()
            return {eid: now - (86400 * (i * 30 + 10)) for i, eid in enumerate(entitlement_ids)}

        try:
            connector = self._router.get("aws")
            return await connector.check_access_usage(entitlement_ids)
        except Exception as exc:
            logger.error(
                "access_review.usage_check_failed",
                error=str(exc),
            )
            return {eid: 0.0 for eid in entitlement_ids}

    async def resolve_identity_status(
        self,
        identity_ids: list[str],
    ) -> dict[str, str]:
        """Resolve current status of identities (active, disabled, terminated).

        Returns mapping of identity_id -> status.
        """
        logger.info(
            "access_review.resolving_identity_status",
            count=len(identity_ids),
        )

        if self._router is None:
            statuses: dict[str, str] = {}
            for i, iid in enumerate(identity_ids):
                if i % 5 == 0:
                    statuses[iid] = "terminated"
                elif i % 3 == 0:
                    statuses[iid] = "disabled"
                else:
                    statuses[iid] = "active"
            return statuses

        try:
            connector = self._router.get("azure")
            return await connector.resolve_identity_status(identity_ids)
        except Exception as exc:
            logger.error(
                "access_review.identity_resolution_failed",
                error=str(exc),
            )
            return {iid: "unknown" for iid in identity_ids}

    async def get_sod_policy(
        self,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Retrieve separation-of-duty policy rules for the tenant.

        Returns list of SoD rules, each with conflicting_permissions
        and scope.
        """
        logger.info(
            "access_review.fetching_sod_policy",
            tenant_id=tenant_id,
        )

        if self._router is None:
            return [
                {
                    "rule_id": "sod-001",
                    "name": "Finance read/write separation",
                    "conflicting_permissions": [
                        "finance:read",
                        "finance:approve",
                    ],
                    "scope": "finance",
                },
                {
                    "rule_id": "sod-002",
                    "name": "IAM admin / audit separation",
                    "conflicting_permissions": [
                        "iam:admin",
                        "audit:read",
                    ],
                    "scope": "security",
                },
                {
                    "rule_id": "sod-003",
                    "name": "PHI access / billing separation",
                    "conflicting_permissions": [
                        "phi:read",
                        "billing:approve",
                    ],
                    "scope": "hipaa",
                },
            ]

        if self._repository:
            try:
                return await self._repository.get_sod_rules(tenant_id)
            except Exception as exc:
                logger.error(
                    "access_review.sod_policy_fetch_failed",
                    error=str(exc),
                )
        return []

    async def submit_certification(
        self,
        task_id: str,
        decision: str,
        certified_by: str,
        notes: str = "",
    ) -> dict[str, Any]:
        """Submit a certification decision for a review task.

        Returns the certification record.
        """
        logger.info(
            "access_review.submitting_certification",
            task_id=task_id,
            decision=decision,
            certified_by=certified_by,
        )

        record = {
            "id": f"cert-{uuid4().hex[:12]}",
            "task_id": task_id,
            "decision": decision,
            "certified_by": certified_by,
            "certified_at": time.time(),
            "notes": notes,
        }

        if self._repository:
            try:
                await self._repository.save_certification(record)
            except Exception as exc:
                logger.error(
                    "access_review.certification_save_failed",
                    error=str(exc),
                )

        return record

    # --- Private helpers ---

    @staticmethod
    def _mock_entitlements(
        tenant_id: str,
        identity_types: list[str],
    ) -> list[dict[str, Any]]:
        """Return mock entitlement data for testing without connectors."""
        now = time.time()
        entitlements: list[dict[str, Any]] = []

        if "human" in identity_types:
            entitlements.extend(
                [
                    {
                        "id": "ent-001",
                        "identity_id": "user-admin-01",
                        "identity_type": "human",
                        "resource": "aws:iam",
                        "permission": "iam:admin",
                        "granted_at": now - 86400 * 365,
                        "last_used": now - 86400 * 2,
                        "granted_by": "system",
                        "justification": "Platform administration",
                    },
                    {
                        "id": "ent-002",
                        "identity_id": "user-admin-01",
                        "identity_type": "human",
                        "resource": "aws:s3:phi-bucket",
                        "permission": "phi:read",
                        "granted_at": now - 86400 * 180,
                        "last_used": now - 86400 * 120,
                        "granted_by": "manager-01",
                        "justification": "Incident investigation",
                    },
                    {
                        "id": "ent-003",
                        "identity_id": "user-dev-01",
                        "identity_type": "human",
                        "resource": "aws:ec2",
                        "permission": "ec2:full_access",
                        "granted_at": now - 86400 * 90,
                        "last_used": now - 86400 * 95,
                        "granted_by": "manager-02",
                        "justification": "Dev environment",
                    },
                    {
                        "id": "ent-004",
                        "identity_id": "user-terminated-01",
                        "identity_type": "human",
                        "resource": "gcp:bigquery",
                        "permission": "bigquery:editor",
                        "granted_at": now - 86400 * 200,
                        "last_used": 0.0,
                        "granted_by": "manager-01",
                        "justification": "Data analysis",
                    },
                    {
                        "id": "ent-005",
                        "identity_id": "user-finance-01",
                        "identity_type": "human",
                        "resource": "finance-system",
                        "permission": "finance:read",
                        "granted_at": now - 86400 * 60,
                        "last_used": now - 86400 * 5,
                        "granted_by": "cfo",
                        "justification": "Financial reporting",
                    },
                    {
                        "id": "ent-006",
                        "identity_id": "user-finance-01",
                        "identity_type": "human",
                        "resource": "finance-system",
                        "permission": "finance:approve",
                        "granted_at": now - 86400 * 30,
                        "last_used": now - 86400 * 3,
                        "granted_by": "cfo",
                        "justification": "Payment approvals",
                    },
                ]
            )

        if "service_account" in identity_types:
            entitlements.extend(
                [
                    {
                        "id": "ent-007",
                        "identity_id": "svc-ci-runner",
                        "identity_type": "service_account",
                        "resource": "aws:ecr",
                        "permission": "ecr:push",
                        "granted_at": now - 86400 * 400,
                        "last_used": now - 86400 * 1,
                        "granted_by": "platform-team",
                        "justification": "CI/CD pipeline",
                    },
                    {
                        "id": "ent-008",
                        "identity_id": "svc-legacy-etl",
                        "identity_type": "service_account",
                        "resource": "aws:rds:production",
                        "permission": "rds:full_access",
                        "granted_at": now - 86400 * 500,
                        "last_used": 0.0,
                        "granted_by": "unknown",
                        "justification": "",
                    },
                ]
            )

        if "ai_agent" in identity_types:
            entitlements.append(
                {
                    "id": "ent-009",
                    "identity_id": "agent-remediation-01",
                    "identity_type": "ai_agent",
                    "resource": "k8s:pods",
                    "permission": "k8s:restart_pod",
                    "granted_at": now - 86400 * 30,
                    "last_used": now - 86400 * 2,
                    "granted_by": "platform-admin",
                    "justification": "Automated remediation",
                },
            )

        return entitlements
