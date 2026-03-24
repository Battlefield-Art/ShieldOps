"""Tool functions for the Identity Graph Agent.

These bridge identity providers, directory services, and cloud IAM
to the agent's LangGraph nodes.
"""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.connectors.base import ConnectorRouter

logger = structlog.get_logger()


class IdentityGraphToolkit:
    """Collection of tools for identity graph discovery and analysis."""

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        repository: Any = None,
    ) -> None:
        self._router = connector_router
        self._repository = repository

    async def scan_directory(
        self,
        target: str,
        identity_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Scan identity directory (Azure AD, Okta, etc.) for all principals."""
        identity_types = identity_types or ["human", "service_account", "ai_agent"]
        logger.info("identity_graph.scanning_directory", target=target, types=identity_types)

        if self._router is None:
            return self._mock_directory_scan(target, identity_types)

        identities: list[dict[str, Any]] = []
        for provider_name in ("azure", "aws", "gcp", "kubernetes"):
            try:
                connector = self._router.get(provider_name)
                provider_identities = await connector.list_identities(
                    target=target, identity_types=identity_types
                )
                identities.extend(provider_identities)
            except (ValueError, AttributeError, Exception) as e:
                logger.warning(
                    "identity_graph.provider_scan_failed",
                    provider=provider_name,
                    error=str(e),
                )
        return identities

    async def enumerate_oauth_grants(
        self,
        target: str,
    ) -> list[dict[str, Any]]:
        """Enumerate OAuth grants and consent for an org/tenant."""
        logger.info("identity_graph.enumerating_oauth_grants", target=target)

        if self._router is None:
            return [
                {
                    "app_name": "analytics-pipeline",
                    "grant_type": "client_credentials",
                    "scopes": ["read_write_all"],
                    "principal_id": "svc-analytics",
                    "last_used": "2025-12-01",
                },
                {
                    "app_name": "legacy-dashboard",
                    "grant_type": "implicit",
                    "scopes": ["full_access"],
                    "principal_id": "app-legacy",
                    "last_used": "2024-06-15",
                },
            ]

        try:
            connector = self._router.get("azure")
            return await connector.list_oauth_grants(target)
        except Exception as e:
            logger.error("identity_graph.oauth_grants_failed", error=str(e))
            return []

    async def map_service_accounts(
        self,
        target: str,
    ) -> list[dict[str, Any]]:
        """Map service accounts across all cloud providers."""
        logger.info("identity_graph.mapping_service_accounts", target=target)

        if self._router is None:
            return [
                {
                    "account_name": "k8s-deployer",
                    "type": "kubernetes_sa",
                    "permissions": ["deploy", "create", "delete"],
                    "owner": "platform-team",
                    "last_used": "2026-03-20",
                },
                {
                    "account_name": "ci-runner",
                    "type": "ci_cd",
                    "permissions": ["read", "write", "admin"],
                    "owner": "unknown",
                    "last_used": "2025-09-01",
                },
            ]

        accounts: list[dict[str, Any]] = []
        for provider_name in ("aws", "gcp", "azure", "kubernetes"):
            try:
                connector = self._router.get(provider_name)
                provider_accounts = await connector.list_service_accounts(target)
                accounts.extend(provider_accounts)
            except (ValueError, AttributeError, Exception) as e:
                logger.warning(
                    "identity_graph.service_account_scan_failed",
                    provider=provider_name,
                    error=str(e),
                )
        return accounts

    async def trace_ai_agent_permissions(
        self,
        target: str,
    ) -> list[dict[str, Any]]:
        """Trace permissions granted to AI agent identities."""
        logger.info("identity_graph.tracing_ai_agent_permissions", target=target)

        if self._router is None:
            return [
                {
                    "agent_id": "agent-remediation-01",
                    "permissions": ["k8s:restart_pod", "k8s:scale", "aws:ec2:reboot"],
                    "delegated_by": "platform-admin",
                    "scope": "production",
                    "last_invoked": "2026-03-23",
                },
            ]

        if self._repository:
            try:
                return await self._repository.list_agent_permissions(target)
            except Exception as e:
                logger.error("identity_graph.ai_agent_perms_failed", error=str(e))
        return []

    async def assess_trust_chain(
        self,
        source_id: str,
        target_id: str,
    ) -> dict[str, Any]:
        """Assess the trust chain between two identities."""
        logger.info("identity_graph.assessing_trust_chain", source=source_id, target=target_id)
        return {
            "source": source_id,
            "target": target_id,
            "path": [source_id, target_id],
            "trust_level": 0.7,
            "relationship_type": "role_assumption",
            "assessed_at": datetime.now(UTC).isoformat(),
        }

    # --- Private helpers ---

    @staticmethod
    def _mock_directory_scan(target: str, identity_types: list[str]) -> list[dict[str, Any]]:
        """Return mock identity data for testing without connectors."""
        identities: list[dict[str, Any]] = []
        if "human" in identity_types:
            identities.extend(
                [
                    {
                        "identity_id": "user-admin-01",
                        "identity_name": "Platform Admin",
                        "identity_type": "human",
                        "provider": "azure_ad",
                        "permissions": ["global_admin", "user_admin", "billing_admin"],
                        "groups": ["admins", "platform-team"],
                        "mfa_enabled": True,
                    },
                    {
                        "identity_id": "user-dev-01",
                        "identity_name": "Developer",
                        "identity_type": "human",
                        "provider": "azure_ad",
                        "permissions": ["reader", "contributor"],
                        "groups": ["developers"],
                        "mfa_enabled": False,
                    },
                ]
            )
        if "service_account" in identity_types:
            identities.append(
                {
                    "identity_id": "svc-ci-runner",
                    "identity_name": "CI Runner",
                    "identity_type": "service_account",
                    "provider": "gcp_iam",
                    "permissions": ["compute.admin", "storage.admin", "iam.serviceAccountUser"],
                    "groups": [],
                    "mfa_enabled": False,
                }
            )
        if "ai_agent" in identity_types:
            identities.append(
                {
                    "identity_id": "agent-remediation",
                    "identity_name": "Remediation Agent",
                    "identity_type": "ai_agent",
                    "provider": "shieldops",
                    "permissions": ["k8s:restart_pod", "k8s:scale", "aws:ec2:reboot"],
                    "groups": ["agents"],
                    "mfa_enabled": False,
                }
            )
        return identities
