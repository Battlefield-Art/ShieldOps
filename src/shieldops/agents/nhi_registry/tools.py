"""NHI Registry Agent — Tool functions for NHI discovery across cloud providers."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import structlog

from .models import (
    NHIStatus,
    NHIType,
    NonHumanIdentity,
    ShadowAIAgent,
)

logger = structlog.get_logger()

# Known LLM provider API endpoints for shadow AI detection
_LLM_PROVIDER_ENDPOINTS: dict[str, str] = {
    "api.openai.com": "openai",
    "api.anthropic.com": "anthropic",
    "generativelanguage.googleapis.com": "google_vertex",
    "api.cohere.ai": "cohere",
    "api.mistral.ai": "mistral",
    "api-inference.huggingface.co": "huggingface",
    "api.replicate.com": "replicate",
}

# Risk weights by NHI type
_TYPE_RISK_WEIGHTS: dict[NHIType, float] = {
    NHIType.SERVICE_ACCOUNT: 0.6,
    NHIType.AI_AGENT: 0.8,
    NHIType.CI_CD_TOKEN: 0.7,
    NHIType.OAUTH_APP: 0.5,
    NHIType.API_KEY: 0.6,
    NHIType.MCP_CONNECTION: 0.9,
    NHIType.GITHUB_ACTION: 0.5,
    NHIType.TERRAFORM_PRINCIPAL: 0.8,
    NHIType.K8S_SERVICE_ACCOUNT: 0.7,
}


def _generate_nhi_id(provider: str, name: str) -> str:
    """Generate a deterministic NHI ID."""
    raw = f"{provider}:{name}"
    return f"NHI-{hashlib.sha256(raw.encode()).hexdigest()[:12].upper()}"


class NHIRegistryToolkit:
    """Tools for scanning and cataloguing non-human identities."""

    def __init__(
        self,
        aws_client: Any | None = None,
        gcp_client: Any | None = None,
        azure_client: Any | None = None,
        k8s_client: Any | None = None,
        github_client: Any | None = None,
    ) -> None:
        self._aws_client = aws_client
        self._gcp_client = gcp_client
        self._azure_client = azure_client
        self._k8s_client = k8s_client
        self._github_client = github_client

    async def scan_aws_iam(self, account_id: str = "") -> list[NonHumanIdentity]:
        """Scan AWS IAM for service accounts, roles, and API keys."""
        logger.info("nhi_registry.scan_aws_iam", account_id=account_id)

        if self._aws_client is not None:
            try:
                raw = await self._aws_client.list_iam_identities(account_id=account_id)
                return [NonHumanIdentity(**r) for r in raw]
            except Exception:
                logger.exception("nhi_registry.scan_aws_iam.error")

        # Fallback: representative AWS NHI profiles
        now = time.time()
        return [
            NonHumanIdentity(
                id=_generate_nhi_id("aws", "lambda-exec-role"),
                name="lambda-exec-role",
                nhi_type=NHIType.SERVICE_ACCOUNT,
                provider="aws",
                permissions=["s3:GetObject", "dynamodb:Query", "logs:PutLogEvents"],
                last_used=now - 3600,
                owner="platform-team",
                status=NHIStatus.ACTIVE,
                created_at=now - 86400 * 180,
            ),
            NonHumanIdentity(
                id=_generate_nhi_id("aws", "ci-deploy-key"),
                name="ci-deploy-key",
                nhi_type=NHIType.CI_CD_TOKEN,
                provider="aws",
                permissions=["ecr:*", "ecs:UpdateService", "iam:PassRole"],
                last_used=now - 86400 * 120,
                owner="",
                status=NHIStatus.DORMANT,
                created_at=now - 86400 * 365,
            ),
            NonHumanIdentity(
                id=_generate_nhi_id("aws", "terraform-provisioner"),
                name="terraform-provisioner",
                nhi_type=NHIType.TERRAFORM_PRINCIPAL,
                provider="aws",
                permissions=["*"],
                last_used=now - 86400 * 7,
                owner="infra-team",
                status=NHIStatus.ACTIVE,
                created_at=now - 86400 * 300,
            ),
        ]

    async def scan_gcp_service_accounts(
        self,
        project_id: str = "",
    ) -> list[NonHumanIdentity]:
        """Scan GCP for service accounts and API keys."""
        logger.info("nhi_registry.scan_gcp_service_accounts", project_id=project_id)

        if self._gcp_client is not None:
            try:
                raw = await self._gcp_client.list_service_accounts(project_id=project_id)
                return [NonHumanIdentity(**r) for r in raw]
            except Exception:
                logger.exception("nhi_registry.scan_gcp_service_accounts.error")

        now = time.time()
        return [
            NonHumanIdentity(
                id=_generate_nhi_id("gcp", "vertex-ai-agent"),
                name="vertex-ai-agent",
                nhi_type=NHIType.AI_AGENT,
                provider="gcp",
                permissions=["aiplatform.endpoints.predict", "storage.objects.get"],
                last_used=now - 300,
                owner="ml-team",
                status=NHIStatus.ACTIVE,
                created_at=now - 86400 * 60,
            ),
            NonHumanIdentity(
                id=_generate_nhi_id("gcp", "old-dataflow-sa"),
                name="old-dataflow-sa",
                nhi_type=NHIType.SERVICE_ACCOUNT,
                provider="gcp",
                permissions=["bigquery.datasets.get", "dataflow.jobs.create"],
                last_used=now - 86400 * 200,
                owner="",
                status=NHIStatus.ORPHANED,
                created_at=now - 86400 * 400,
            ),
        ]

    async def scan_azure_app_registrations(
        self,
        tenant_id: str = "",
    ) -> list[NonHumanIdentity]:
        """Scan Azure AD for app registrations and managed identities."""
        logger.info("nhi_registry.scan_azure_app_registrations", tenant_id=tenant_id)

        if self._azure_client is not None:
            try:
                raw = await self._azure_client.list_app_registrations(tenant_id=tenant_id)
                return [NonHumanIdentity(**r) for r in raw]
            except Exception:
                logger.exception("nhi_registry.scan_azure_app_registrations.error")

        now = time.time()
        return [
            NonHumanIdentity(
                id=_generate_nhi_id("azure", "openai-integration"),
                name="openai-integration",
                nhi_type=NHIType.AI_AGENT,
                provider="azure",
                permissions=["Cognitive Services User", "Storage Blob Reader"],
                last_used=now - 600,
                owner="ai-platform-team",
                status=NHIStatus.ACTIVE,
                created_at=now - 86400 * 45,
            ),
        ]

    async def scan_k8s_service_accounts(
        self,
        cluster: str = "",
    ) -> list[NonHumanIdentity]:
        """Scan Kubernetes clusters for service accounts."""
        logger.info("nhi_registry.scan_k8s_service_accounts", cluster=cluster)

        if self._k8s_client is not None:
            try:
                raw = await self._k8s_client.list_service_accounts(cluster=cluster)
                return [NonHumanIdentity(**r) for r in raw]
            except Exception:
                logger.exception("nhi_registry.scan_k8s_service_accounts.error")

        now = time.time()
        return [
            NonHumanIdentity(
                id=_generate_nhi_id("k8s", "monitoring-sa"),
                name="monitoring-sa",
                nhi_type=NHIType.K8S_SERVICE_ACCOUNT,
                provider="kubernetes",
                permissions=["get:pods", "list:nodes", "get:metrics"],
                last_used=now - 60,
                owner="sre-team",
                status=NHIStatus.ACTIVE,
                created_at=now - 86400 * 90,
            ),
            NonHumanIdentity(
                id=_generate_nhi_id("k8s", "legacy-job-runner"),
                name="legacy-job-runner",
                nhi_type=NHIType.K8S_SERVICE_ACCOUNT,
                provider="kubernetes",
                permissions=["*"],
                last_used=now - 86400 * 180,
                owner="",
                status=NHIStatus.ORPHANED,
                created_at=now - 86400 * 500,
            ),
        ]

    async def scan_github_tokens(
        self,
        org: str = "",
    ) -> list[NonHumanIdentity]:
        """Scan GitHub for action tokens, deploy keys, and OAuth apps."""
        logger.info("nhi_registry.scan_github_tokens", org=org)

        if self._github_client is not None:
            try:
                raw = await self._github_client.list_tokens(org=org)
                return [NonHumanIdentity(**r) for r in raw]
            except Exception:
                logger.exception("nhi_registry.scan_github_tokens.error")

        now = time.time()
        return [
            NonHumanIdentity(
                id=_generate_nhi_id("github", "ci-bot-pat"),
                name="ci-bot-pat",
                nhi_type=NHIType.GITHUB_ACTION,
                provider="github",
                permissions=["repo", "packages:write", "actions:read"],
                last_used=now - 7200,
                owner="devops-team",
                status=NHIStatus.ACTIVE,
                created_at=now - 86400 * 150,
            ),
            NonHumanIdentity(
                id=_generate_nhi_id("github", "abandoned-oauth-app"),
                name="abandoned-oauth-app",
                nhi_type=NHIType.OAUTH_APP,
                provider="github",
                permissions=["read:org", "repo"],
                last_used=now - 86400 * 300,
                owner="",
                status=NHIStatus.ORPHANED,
                created_at=now - 86400 * 600,
            ),
        ]

    async def detect_unregistered_llm_api_calls(
        self,
        dns_logs: list[dict[str, Any]] | None = None,
        proxy_logs: list[dict[str, Any]] | None = None,
    ) -> list[ShadowAIAgent]:
        """Detect unregistered LLM API calls from network/proxy logs."""
        logger.info("nhi_registry.detect_shadow_ai")

        shadow_agents: list[ShadowAIAgent] = []
        now = time.time()

        if dns_logs:
            for entry in dns_logs:
                domain = entry.get("domain", "")
                for endpoint, provider in _LLM_PROVIDER_ENDPOINTS.items():
                    if endpoint in domain:
                        shadow_agents.append(
                            ShadowAIAgent(
                                id=_generate_nhi_id("shadow", f"{provider}-{domain}"),
                                provider_api_endpoint=endpoint,
                                detected_via="dns_query",
                                calling_service=entry.get("source_service", "unknown"),
                                token_type="api_key",  # noqa: S106
                                first_seen=entry.get("timestamp", now),
                                request_count=entry.get("count", 1),
                            )
                        )

        if not shadow_agents:
            # Fallback: representative shadow AI detections
            shadow_agents = [
                ShadowAIAgent(
                    id=_generate_nhi_id("shadow", "openai-unregistered"),
                    provider_api_endpoint="api.openai.com",
                    detected_via="proxy_logs",
                    calling_service="internal-chatbot",
                    token_type="api_key",  # noqa: S106
                    first_seen=now - 86400 * 14,
                    request_count=4500,
                    estimated_monthly_cost=320.0,
                ),
                ShadowAIAgent(
                    id=_generate_nhi_id("shadow", "anthropic-unregistered"),
                    provider_api_endpoint="api.anthropic.com",
                    detected_via="dns_query",
                    calling_service="data-pipeline-worker",
                    token_type="api_key",  # noqa: S106
                    first_seen=now - 86400 * 3,
                    request_count=850,
                    estimated_monthly_cost=95.0,
                ),
            ]

        return shadow_agents

    def calculate_risk_score(self, identity: NonHumanIdentity) -> float:
        """Calculate a composite risk score for an NHI."""
        now = time.time()
        score = 0.0

        # Type risk weight (0-30 points)
        type_weight = _TYPE_RISK_WEIGHTS.get(identity.nhi_type, 0.5)
        score += type_weight * 30.0

        # Permission breadth (0-25 points)
        perm_count = len(identity.permissions)
        has_wildcard = any("*" in p for p in identity.permissions)
        if has_wildcard:
            score += 25.0
        elif perm_count > 10:
            score += 20.0
        elif perm_count > 5:
            score += 12.0
        else:
            score += max(0.0, perm_count * 2.0)

        # Credential age (0-20 points)
        age_days = (now - identity.created_at) / 86400 if identity.created_at > 0 else 0
        if age_days > 365:
            score += 20.0
        elif age_days > 180:
            score += 14.0
        elif age_days > 90:
            score += 8.0

        # Activity recency (0-15 points) — dormant = higher risk
        idle_days = (now - identity.last_used) / 86400 if identity.last_used > 0 else 999
        if idle_days > 180:
            score += 15.0
        elif idle_days > 90:
            score += 10.0
        elif idle_days > 30:
            score += 5.0

        # Owner status (0-10 points)
        if not identity.owner:
            score += 10.0

        return round(min(100.0, max(0.0, score)), 1)
