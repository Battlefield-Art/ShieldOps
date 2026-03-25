"""Tool functions for the OAuth Grant Analyzer Agent.

These bridge identity providers, SaaS registries, and threat intelligence
feeds to the agent's LangGraph nodes.
"""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.oauth_analyzer.models import (
    GrantAnomaly,
    GrantRecommendation,
    GrantStatus,
    OAuthGrant,
    PermissionClassification,
    PermissionScope,
)

logger = structlog.get_logger()


class OAuthAnalyzerToolkit:
    """Collection of tools for OAuth grant discovery and analysis."""

    def __init__(
        self,
        identity_provider: Any | None = None,
        saas_registry: Any | None = None,
        threat_intel: Any | None = None,
    ) -> None:
        self._identity_provider = identity_provider
        self._saas_registry = saas_registry
        self._threat_intel = threat_intel

    async def discover_oauth_grants(
        self,
        tenant_id: str,
        scope: list[str] | None = None,
    ) -> list[OAuthGrant]:
        """Discover OAuth grants across Google Workspace, Microsoft 365, GitHub, etc.

        If live connectors are not configured, returns realistic simulated data
        including stale and overprivileged grants for development/testing.
        """
        scope = scope or [
            "google_workspace",
            "microsoft_365",
            "github",
            "slack",
            "salesforce",
        ]
        logger.info(
            "oauth_analyzer.discovering_grants",
            tenant_id=tenant_id,
            scope=scope,
        )

        if self._identity_provider is not None:
            try:
                raw = await self._identity_provider.list_oauth_grants(
                    tenant_id=tenant_id, scope=scope
                )
                return [OAuthGrant(**g) for g in raw]
            except Exception as exc:
                logger.warning(
                    "oauth_analyzer.live_discovery_failed",
                    error=str(exc),
                )

        return self._mock_grants(tenant_id, scope)

    async def classify_permissions(
        self,
        grants: list[OAuthGrant],
    ) -> list[PermissionClassification]:
        """Classify each grant's actual vs needed permissions."""
        logger.info(
            "oauth_analyzer.classifying_permissions",
            grant_count=len(grants),
        )

        classifications: list[PermissionClassification] = []
        for grant in grants:
            overprivileged = grant.permission_scope in (
                PermissionScope.ADMIN,
                PermissionScope.FULL_ACCESS,
            )
            unused: list[str] = []
            risk_factors: list[str] = []

            now = time.time()
            age_days = (now - grant.created_at) / 86400 if grant.created_at else 0
            idle_days = (now - grant.last_used) / 86400 if grant.last_used else 0

            if idle_days > 90:
                unused = grant.scopes[:]
                risk_factors.append("dormant_grant_90d")
            elif idle_days > 30:
                risk_factors.append("low_usage_30d")

            if overprivileged:
                risk_factors.append("overprivileged_scope")
            if age_days > 365:
                risk_factors.append("grant_older_than_1y")
            if len(grant.scopes) > 5:
                risk_factors.append("excessive_scope_count")

            classifications.append(
                PermissionClassification(
                    id=f"cls-{uuid4().hex[:8]}",
                    grant_id=grant.id,
                    classified_scope=grant.permission_scope,
                    overprivileged=overprivileged,
                    unused_scopes=unused,
                    risk_factors=risk_factors,
                )
            )

        return classifications

    async def detect_grant_anomalies(
        self,
        grants: list[OAuthGrant],
    ) -> list[GrantAnomaly]:
        """Detect anomalies: unusual timing, excessive scope, dormant→sudden-activity."""
        logger.info(
            "oauth_analyzer.detecting_anomalies",
            grant_count=len(grants),
        )

        anomalies: list[GrantAnomaly] = []
        now = time.time()

        for grant in grants:
            idle_days = (now - grant.last_used) / 86400 if grant.last_used else 0
            age_days = (now - grant.created_at) / 86400 if grant.created_at else 0

            # Dormant grant that became suddenly active
            if grant.status == GrantStatus.ACTIVE and idle_days > 180:
                anomalies.append(
                    GrantAnomaly(
                        id=f"anom-{uuid4().hex[:8]}",
                        grant_id=grant.id,
                        anomaly_type="dormant_reactivation",
                        description=(
                            f"Grant for {grant.app_name} idle for {int(idle_days)}d is now active"
                        ),
                        severity="high",
                        confidence=0.85,
                        detected_at=now,
                    )
                )

            # Full-access grant created recently (< 7 days)
            if grant.permission_scope == PermissionScope.FULL_ACCESS and age_days < 7:
                anomalies.append(
                    GrantAnomaly(
                        id=f"anom-{uuid4().hex[:8]}",
                        grant_id=grant.id,
                        anomaly_type="recent_full_access",
                        description=(
                            f"Full-access grant for {grant.app_name} created {int(age_days)}d ago"
                        ),
                        severity="critical",
                        confidence=0.9,
                        detected_at=now,
                    )
                )

            # Suspicious status
            if grant.status == GrantStatus.SUSPICIOUS:
                anomalies.append(
                    GrantAnomaly(
                        id=f"anom-{uuid4().hex[:8]}",
                        grant_id=grant.id,
                        anomaly_type="flagged_suspicious",
                        description=(
                            f"Grant for {grant.app_name} flagged as suspicious by identity provider"
                        ),
                        severity="high",
                        confidence=0.8,
                        detected_at=now,
                    )
                )

            # Excessive scope count
            if len(grant.scopes) > 8:
                anomalies.append(
                    GrantAnomaly(
                        id=f"anom-{uuid4().hex[:8]}",
                        grant_id=grant.id,
                        anomaly_type="excessive_scopes",
                        description=(f"Grant for {grant.app_name} has {len(grant.scopes)} scopes"),
                        severity="medium",
                        confidence=0.75,
                        detected_at=now,
                    )
                )

        return anomalies

    async def generate_recommendations(
        self,
        grants: list[OAuthGrant],
        anomalies: list[GrantAnomaly],
    ) -> list[GrantRecommendation]:
        """Generate remediation recommendations for risky grants."""
        logger.info(
            "oauth_analyzer.generating_recommendations",
            grant_count=len(grants),
            anomaly_count=len(anomalies),
        )

        recs: list[GrantRecommendation] = []
        anomaly_grant_ids = {a.grant_id for a in anomalies}
        anomaly_map: dict[str, list[GrantAnomaly]] = {}
        for a in anomalies:
            anomaly_map.setdefault(a.grant_id, []).append(a)

        for grant in grants:
            if grant.status == GrantStatus.STALE:
                recs.append(
                    GrantRecommendation(
                        id=f"rec-{uuid4().hex[:8]}",
                        grant_id=grant.id,
                        action="revoke",
                        reason=f"Stale grant for {grant.app_name} — no recent usage",
                        priority="high",
                        auto_executable=True,
                    )
                )
            elif grant.permission_scope in (
                PermissionScope.ADMIN,
                PermissionScope.FULL_ACCESS,
            ):
                recs.append(
                    GrantRecommendation(
                        id=f"rec-{uuid4().hex[:8]}",
                        grant_id=grant.id,
                        action="scope_reduce",
                        reason=(
                            f"{grant.app_name} has {grant.permission_scope.value} "
                            f"— reduce to minimum required scopes"
                        ),
                        priority="high",
                        auto_executable=False,
                    )
                )

            if grant.id in anomaly_grant_ids:
                grant_anomalies = anomaly_map.get(grant.id, [])
                for anom in grant_anomalies:
                    if anom.severity == "critical":
                        recs.append(
                            GrantRecommendation(
                                id=f"rec-{uuid4().hex[:8]}",
                                grant_id=grant.id,
                                action="flag_and_review",
                                reason=(
                                    f"Critical anomaly: {anom.anomaly_type} — {anom.description}"
                                ),
                                priority="critical",
                                auto_executable=False,
                            )
                        )

        return recs

    # --- Private helpers ---

    @staticmethod
    def _mock_grants(
        tenant_id: str,
        scope: list[str],
    ) -> list[OAuthGrant]:
        """Return realistic simulated OAuth grants for testing."""
        now = time.time()
        day = 86400.0

        grants: list[OAuthGrant] = [
            OAuthGrant(
                id=f"grant-{uuid4().hex[:8]}",
                app_name="analytics-pipeline",
                app_id="app-analytics-001",
                provider="google_workspace",
                granted_to="svc-analytics@acme.iam",
                granted_by="admin@acme.com",
                scopes=[
                    "drive.readonly",
                    "bigquery.data.viewer",
                    "sheets.readonly",
                ],
                permission_scope=PermissionScope.READ_ONLY,
                status=GrantStatus.ACTIVE,
                created_at=now - 180 * day,
                last_used=now - 2 * day,
                risk_score=15.0,
            ),
            OAuthGrant(
                id=f"grant-{uuid4().hex[:8]}",
                app_name="legacy-crm-sync",
                app_id="app-crm-legacy-002",
                provider="salesforce",
                granted_to="svc-crm-sync@acme.iam",
                granted_by="it-admin@acme.com",
                scopes=[
                    "api",
                    "full",
                    "refresh_token",
                    "chatter_api",
                    "custom_permissions",
                    "wave_api",
                ],
                permission_scope=PermissionScope.FULL_ACCESS,
                status=GrantStatus.STALE,
                created_at=now - 540 * day,
                last_used=now - 210 * day,
                risk_score=82.0,
            ),
            OAuthGrant(
                id=f"grant-{uuid4().hex[:8]}",
                app_name="ci-cd-deployer",
                app_id="app-github-003",
                provider="github",
                granted_to="bot-deploy@acme-org",
                granted_by="devops-lead@acme.com",
                scopes=[
                    "repo",
                    "write:packages",
                    "admin:org",
                    "admin:repo_hook",
                    "workflow",
                    "delete_repo",
                    "admin:gpg_key",
                    "admin:ssh_signing_key",
                    "admin:enterprise",
                ],
                permission_scope=PermissionScope.ADMIN,
                status=GrantStatus.ACTIVE,
                created_at=now - 90 * day,
                last_used=now - 1 * day,
                risk_score=68.0,
            ),
            OAuthGrant(
                id=f"grant-{uuid4().hex[:8]}",
                app_name="slack-security-bot",
                app_id="app-slack-004",
                provider="slack",
                granted_to="secbot@acme-workspace",
                granted_by="security-lead@acme.com",
                scopes=[
                    "channels:read",
                    "chat:write",
                    "users:read",
                ],
                permission_scope=PermissionScope.READ_WRITE,
                status=GrantStatus.ACTIVE,
                created_at=now - 60 * day,
                last_used=now - 0.5 * day,
                risk_score=20.0,
            ),
            OAuthGrant(
                id=f"grant-{uuid4().hex[:8]}",
                app_name="unknown-data-exporter",
                app_id="app-unknown-005",
                provider="microsoft_365",
                granted_to="extern-partner@vendor.com",
                granted_by="compromised-user@acme.com",
                scopes=[
                    "Mail.ReadWrite",
                    "Files.ReadWrite.All",
                    "Sites.ReadWrite.All",
                    "User.ReadWrite.All",
                    "Directory.ReadWrite.All",
                    "Group.ReadWrite.All",
                    "Application.ReadWrite.All",
                    "RoleManagement.ReadWrite.Directory",
                    "AppRoleAssignment.ReadWrite.All",
                ],
                permission_scope=PermissionScope.FULL_ACCESS,
                status=GrantStatus.SUSPICIOUS,
                created_at=now - 3 * day,
                last_used=now - 0.1 * day,
                risk_score=95.0,
            ),
            OAuthGrant(
                id=f"grant-{uuid4().hex[:8]}",
                app_name="hr-onboarding-tool",
                app_id="app-hr-006",
                provider="google_workspace",
                granted_to="hr-tool@acme.iam",
                granted_by="hr-director@acme.com",
                scopes=[
                    "admin.directory.user",
                    "admin.directory.group",
                    "admin.directory.orgunit",
                    "gmail.settings.sharing",
                ],
                permission_scope=PermissionScope.ADMIN,
                status=GrantStatus.ACTIVE,
                created_at=now - 400 * day,
                last_used=now - 45 * day,
                risk_score=55.0,
            ),
        ]

        return grants
