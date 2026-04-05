"""Tool functions for the Identity Graph Agent.

These bridge identity providers, directory services, and cloud IAM
to the agent's LangGraph nodes.  Includes NHI (non-human identity)
discovery, classification, risk scoring, relationship mapping,
anomaly detection, and governance reporting.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from shieldops.connectors.base import ConnectorRouter

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Risk-scoring constants
# ---------------------------------------------------------------------------
_ADMIN_KEYWORDS: set[str] = {
    "admin",
    "root",
    "superuser",
    "global_admin",
    "owner",
    "iam.admin",
    "compute.admin",
    "storage.admin",
    "iam:*",
    "ec2:*",
    "s3:*",
    "AdministratorAccess",
}

_NHI_TYPES: set[str] = {
    "service_account",
    "api_key",
    "oauth_token",
    "iam_role",
    "bot_account",
}

_CREDENTIAL_ROTATION_DAYS = 90
_STALE_THRESHOLD_DAYS = 90


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
                provider_identities = await connector.list_identities(  # type: ignore[attr-defined]
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
            return await connector.list_oauth_grants(  # type: ignore[attr-defined]
                target
            )
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
                provider_accounts = await connector.list_service_accounts(  # type: ignore[attr-defined]
                    target
                )
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

    # ------------------------------------------------------------------
    # NHI (Non-Human Identity) discovery & risk scoring
    # ------------------------------------------------------------------

    async def discover_identities(self, context: dict[str, Any]) -> dict[str, Any]:
        """Discover non-human identities across cloud providers.

        Queries AWS IAM (users, roles, access keys, service accounts) and
        falls back to heuristic sample data when connectors are unavailable.

        Returns:
            dict with ``identities`` list and ``total_discovered`` count.
        """
        environment = context.get("environment", "production")
        filters = context.get("filters", {})
        identities: list[dict[str, Any]] = []

        if self._router is not None:
            for provider_name in ("aws", "gcp", "azure", "kubernetes"):
                try:
                    connector = self._router.get(provider_name)
                    resources = await connector.list_resources(
                        "iam_user",
                        environment,
                        filters,
                    )
                    for r in resources:
                        identities.append(
                            {
                                "id": getattr(r, "id", str(r)),
                                "name": getattr(r, "name", str(r)),
                                "type": "iam_user",
                                "provider": provider_name,
                                "metadata": getattr(r, "metadata", {}),
                                "created_at": getattr(r, "created_at", None),
                                "last_used": getattr(r, "last_used", None),
                                "mfa_enabled": False,
                                "permissions": [],
                            }
                        )
                except Exception as exc:
                    logger.warning(
                        "identity_graph.discover.provider_error",
                        provider=provider_name,
                        error=str(exc),
                    )

        if not identities:
            identities = self._generate_sample_inventory(context)

        logger.info(
            "identity_graph.discover.complete",
            total=len(identities),
        )
        return {"identities": identities, "total_discovered": len(identities)}

    def classify_identity_type(self, identity: dict[str, Any]) -> dict[str, Any]:
        """Classify an identity as a specific NHI type.

        Classification hierarchy:
        - ``bot_account`` — name contains "bot" or "automation"
        - ``oauth_token`` — has grant_type or token metadata
        - ``api_key`` — has access_key or api_key metadata
        - ``iam_role`` — type contains "role"
        - ``service_account`` — default for all other NHIs

        Returns:
            dict with ``identity_id``, ``classification``, ``confidence``,
            and ``classification_signals``.
        """
        name = (identity.get("name") or identity.get("id") or "").lower()
        id_type = (identity.get("type") or "").lower()
        metadata = identity.get("metadata") or {}
        signals: list[str] = []

        # Determine classification
        classification = "service_account"
        confidence = 0.6

        if any(kw in name for kw in ("bot", "automation", "scheduler", "cron")):
            classification = "bot_account"
            confidence = 0.85
            signals.append(f"name_pattern:{name}")
        elif metadata.get("grant_type") or "oauth" in id_type:
            classification = "oauth_token"
            confidence = 0.9
            signals.append("grant_type_present")
        elif metadata.get("access_key_id") or "api_key" in id_type or "key" in name:
            classification = "api_key"
            confidence = 0.85
            signals.append("access_key_metadata")
        elif "role" in id_type:
            classification = "iam_role"
            confidence = 0.9
            signals.append("type_is_role")
        else:
            signals.append("default_service_account")

        return {
            "identity_id": identity.get("id", ""),
            "classification": classification,
            "confidence": confidence,
            "classification_signals": signals,
        }

    def assess_risk(self, identity: dict[str, Any]) -> dict[str, Any]:
        """Score risk for a single identity on a 0-100 scale.

        Factors (additive, capped at 100):
        - Privilege level: admin/root keywords → +35
        - Credential age: >90 days → +20
        - Last-used staleness: >90 days unused → +20
        - MFA status: missing → +15
        - Excessive permissions count (>5) → +10

        Returns:
            dict with ``identity_id``, ``risk_score``, ``risk_level``,
            ``risk_factors``, and ``recommendations``.
        """
        score = 0.0
        factors: list[str] = []
        recommendations: list[str] = []
        permissions = identity.get("permissions") or []
        now = datetime.now(UTC)

        # 1. Privilege level
        perm_set = {p.lower() for p in permissions}
        if perm_set & _ADMIN_KEYWORDS:
            score += 35
            factors.append("admin_privileges")
            recommendations.append("Apply least-privilege: remove admin permissions")

        # 2. Credential age
        created_at = identity.get("created_at")
        if isinstance(created_at, str):
            try:
                created_at = datetime.fromisoformat(created_at)
            except (ValueError, TypeError):
                created_at = None
        if isinstance(created_at, datetime):
            age_days = (now - created_at.replace(tzinfo=UTC)).days
            if age_days > _CREDENTIAL_ROTATION_DAYS:
                score += 20
                factors.append(f"credential_age_{age_days}d")
                recommendations.append(
                    f"Rotate credentials (age: {age_days}d, max: {_CREDENTIAL_ROTATION_DAYS}d)"
                )

        # 3. Last-used staleness
        last_used = identity.get("last_used")
        if isinstance(last_used, str):
            try:
                last_used = datetime.fromisoformat(last_used)
            except (ValueError, TypeError):
                last_used = None
        if isinstance(last_used, datetime):
            idle_days = (now - last_used.replace(tzinfo=UTC)).days
            if idle_days > _STALE_THRESHOLD_DAYS:
                score += 20
                factors.append(f"stale_credential_{idle_days}d")
                recommendations.append(
                    f"Disable or delete stale identity (unused {idle_days} days)"
                )
        elif last_used is None:
            # Never used is risky
            score += 10
            factors.append("never_used")
            recommendations.append("Investigate never-used identity")

        # 4. MFA status
        if not identity.get("mfa_enabled", False):
            score += 15
            factors.append("no_mfa")
            recommendations.append("Enable MFA or enforce hardware token")

        # 5. Excessive permissions
        if len(permissions) > 5:
            score += 10
            factors.append(f"excessive_permissions_{len(permissions)}")
            recommendations.append("Review and reduce permission count")

        score = min(score, 100.0)

        if score >= 70:
            risk_level = "critical"
        elif score >= 50:
            risk_level = "high"
        elif score >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "identity_id": identity.get("id", ""),
            "risk_score": score,
            "risk_level": risk_level,
            "risk_factors": factors,
            "recommendations": recommendations,
        }

    def map_relationships(self, identities: list[dict[str, Any]]) -> dict[str, Any]:
        """Map trust relationships between identities.

        Detects:
        - Role assumption chains (same provider, overlapping permissions)
        - Cross-account access (different providers, shared permissions)
        - Group co-membership

        Returns:
            dict with ``relationships`` list, ``relationship_count``,
            and ``cross_account_count``.
        """
        relationships: list[dict[str, Any]] = []
        cross_account = 0

        # Index by provider for cross-account detection
        by_provider: dict[str, list[dict[str, Any]]] = {}
        for ident in identities:
            provider = ident.get("provider", "unknown")
            by_provider.setdefault(provider, []).append(ident)

        # Intra-provider: detect role assumption via overlapping permissions
        for provider, group in by_provider.items():
            for i, a in enumerate(group):
                a_perms = set(a.get("permissions") or [])
                if not a_perms:
                    continue
                for b in group[i + 1 :]:
                    b_perms = set(b.get("permissions") or [])
                    overlap = a_perms & b_perms
                    if overlap:
                        relationships.append(
                            {
                                "source_id": a.get("id", ""),
                                "target_id": b.get("id", ""),
                                "relationship_type": "role_assumption",
                                "provider": provider,
                                "shared_permissions": sorted(overlap),
                                "trust_level": min(len(overlap) / max(len(a_perms), 1), 1.0),
                            }
                        )

        # Cross-provider: detect shared permission patterns
        providers = list(by_provider.keys())
        for pi in range(len(providers)):
            for pj in range(pi + 1, len(providers)):
                for a in by_provider[providers[pi]]:
                    a_perms = set(a.get("permissions") or [])
                    for b in by_provider[providers[pj]]:
                        b_perms = set(b.get("permissions") or [])
                        # Normalize: check for semantic overlap (admin in both)
                        a_admin = a_perms & _ADMIN_KEYWORDS
                        b_admin = b_perms & _ADMIN_KEYWORDS
                        if a_admin and b_admin:
                            cross_account += 1
                            relationships.append(
                                {
                                    "source_id": a.get("id", ""),
                                    "target_id": b.get("id", ""),
                                    "relationship_type": "cross_account_access",
                                    "providers": [providers[pi], providers[pj]],
                                    "shared_admin": True,
                                    "trust_level": 0.8,
                                }
                            )

        return {
            "relationships": relationships,
            "relationship_count": len(relationships),
            "cross_account_count": cross_account,
        }

    def detect_anomalies(self, identity: dict[str, Any]) -> dict[str, Any]:
        """Detect anomalies for a single identity.

        Checks:
        - Over-privileged service accounts (admin + service_account)
        - Unused credentials (>90 days since last use)
        - Keys without rotation (created >90 days ago, never rotated)
        - Bot accounts with write permissions
        - Never-used identities

        Returns:
            dict with ``identity_id``, ``anomalies`` list,
            ``anomaly_count``, and ``severity``.
        """
        anomalies: list[dict[str, Any]] = []
        now = datetime.now(UTC)
        permissions = identity.get("permissions") or []
        perm_lower = {p.lower() for p in permissions}
        id_type = (identity.get("type") or "").lower()
        name = (identity.get("name") or "").lower()

        # 1. Over-privileged service account
        if id_type in ("service_account", "iam_role") and perm_lower & _ADMIN_KEYWORDS:
            anomalies.append(
                {
                    "type": "over_privileged_service_account",
                    "severity": "critical",
                    "detail": f"Service account has admin privileges: "
                    f"{sorted(perm_lower & _ADMIN_KEYWORDS)}",
                    "recommendation": "Restrict to least-privilege permissions",
                }
            )

        # 2. Unused credentials (>90 days)
        last_used = identity.get("last_used")
        if isinstance(last_used, str):
            try:
                last_used = datetime.fromisoformat(last_used)
            except (ValueError, TypeError):
                last_used = None
        if isinstance(last_used, datetime):
            idle_days = (now - last_used.replace(tzinfo=UTC)).days
            if idle_days > _STALE_THRESHOLD_DAYS:
                anomalies.append(
                    {
                        "type": "unused_credentials",
                        "severity": "high",
                        "detail": f"Credentials unused for {idle_days} days",
                        "recommendation": "Disable or delete the identity",
                    }
                )

        # 3. Keys without rotation
        created_at = identity.get("created_at")
        if isinstance(created_at, str):
            try:
                created_at = datetime.fromisoformat(created_at)
            except (ValueError, TypeError):
                created_at = None
        last_rotated = identity.get("last_rotated") or identity.get("metadata", {}).get(
            "last_rotated"
        )
        if isinstance(created_at, datetime) and not last_rotated:
            age_days = (now - created_at.replace(tzinfo=UTC)).days
            if age_days > _CREDENTIAL_ROTATION_DAYS:
                anomalies.append(
                    {
                        "type": "key_without_rotation",
                        "severity": "high",
                        "detail": f"Key created {age_days} days ago, never rotated",
                        "recommendation": f"Rotate key (max: {_CREDENTIAL_ROTATION_DAYS}d)",
                    }
                )

        # 4. Bot with write permissions
        if any(kw in name for kw in ("bot", "automation")):
            write_perms = {
                p
                for p in perm_lower
                if any(w in p for w in ("write", "delete", "create", "admin", "put"))
            }
            if write_perms:
                anomalies.append(
                    {
                        "type": "bot_with_write_access",
                        "severity": "medium",
                        "detail": f"Bot account has write permissions: {sorted(write_perms)}",
                        "recommendation": "Restrict bot to read-only where possible",
                    }
                )

        # 5. Never-used identity
        if identity.get("last_used") is None and identity.get("created_at"):
            anomalies.append(
                {
                    "type": "never_used_identity",
                    "severity": "medium",
                    "detail": "Identity was created but never used",
                    "recommendation": "Investigate purpose or delete",
                }
            )

        # Determine overall severity
        if any(a["severity"] == "critical" for a in anomalies):
            severity = "critical"
        elif any(a["severity"] == "high" for a in anomalies):
            severity = "high"
        elif anomalies:
            severity = "medium"
        else:
            severity = "none"

        return {
            "identity_id": identity.get("id", ""),
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "severity": severity,
        }

    def generate_report(self, inventory: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate an NHI governance report.

        Produces risk distribution, top risks, and actionable
        recommendations from the identity inventory.

        Returns:
            dict with ``total_identities``, ``risk_distribution``,
            ``top_risks``, ``anomaly_summary``, ``recommendations``,
            and ``generated_at``.
        """
        risk_distribution: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        top_risks: list[dict[str, Any]] = []
        all_anomalies: list[dict[str, Any]] = []
        recommendation_set: set[str] = set()

        for ident in inventory:
            risk = self.assess_risk(ident)
            risk_distribution[risk["risk_level"]] += 1

            if risk["risk_score"] >= 50:
                top_risks.append(
                    {
                        "identity_id": ident.get("id", ""),
                        "name": ident.get("name", ""),
                        "provider": ident.get("provider", ""),
                        "risk_score": risk["risk_score"],
                        "risk_level": risk["risk_level"],
                        "factors": risk["risk_factors"],
                    }
                )

            for rec in risk["recommendations"]:
                recommendation_set.add(rec)

            anomaly_result = self.detect_anomalies(ident)
            if anomaly_result["anomaly_count"] > 0:
                all_anomalies.append(anomaly_result)

        # Sort top risks descending
        top_risks.sort(key=lambda r: r["risk_score"], reverse=True)

        # Build anomaly type summary
        anomaly_type_counts: dict[str, int] = {}
        for ar in all_anomalies:
            for a in ar["anomalies"]:
                atype = a["type"]
                anomaly_type_counts[atype] = anomaly_type_counts.get(atype, 0) + 1

        return {
            "total_identities": len(inventory),
            "risk_distribution": risk_distribution,
            "top_risks": top_risks[:20],
            "anomaly_summary": {
                "total_anomalous_identities": len(all_anomalies),
                "anomaly_types": anomaly_type_counts,
            },
            "recommendations": sorted(recommendation_set),
            "generated_at": datetime.now(UTC).isoformat(),
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

    @staticmethod
    def _generate_sample_inventory(context: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate realistic sample NHI inventory for heuristic fallback."""
        now = datetime.now(UTC)
        env = context.get("environment", "production")
        return [
            {
                "id": "svc-deploy-bot",
                "name": "deploy-bot",
                "type": "service_account",
                "provider": "aws",
                "permissions": ["ec2:*", "s3:*", "iam:PassRole"],
                "mfa_enabled": False,
                "created_at": (now - timedelta(days=200)).isoformat(),
                "last_used": (now - timedelta(days=5)).isoformat(),
                "metadata": {"environment": env},
            },
            {
                "id": "role-lambda-exec",
                "name": "lambda-execution-role",
                "type": "iam_role",
                "provider": "aws",
                "permissions": ["lambda:InvokeFunction", "logs:CreateLogGroup"],
                "mfa_enabled": False,
                "created_at": (now - timedelta(days=120)).isoformat(),
                "last_used": (now - timedelta(days=1)).isoformat(),
                "metadata": {"environment": env},
            },
            {
                "id": "key-ci-pipeline",
                "name": "ci-pipeline-key",
                "type": "api_key",
                "provider": "aws",
                "permissions": ["ecr:GetAuthorizationToken", "ecr:BatchGetImage"],
                "mfa_enabled": False,
                "created_at": (now - timedelta(days=95)).isoformat(),
                "last_used": (now - timedelta(days=100)).isoformat(),
                "metadata": {"environment": env},
            },
            {
                "id": "oauth-analytics",
                "name": "analytics-oauth-app",
                "type": "oauth_token",
                "provider": "gcp",
                "permissions": ["bigquery.dataViewer", "storage.objectViewer"],
                "mfa_enabled": False,
                "created_at": (now - timedelta(days=60)).isoformat(),
                "last_used": (now - timedelta(days=2)).isoformat(),
                "metadata": {"grant_type": "client_credentials", "environment": env},
            },
            {
                "id": "bot-slack-alerts",
                "name": "slack-alert-bot",
                "type": "bot_account",
                "provider": "aws",
                "permissions": ["sns:Publish", "sqs:SendMessage", "s3:PutObject"],
                "mfa_enabled": False,
                "created_at": (now - timedelta(days=180)).isoformat(),
                "last_used": (now - timedelta(days=1)).isoformat(),
                "metadata": {"environment": env},
            },
            {
                "id": "svc-stale-legacy",
                "name": "legacy-migration-svc",
                "type": "service_account",
                "provider": "azure",
                "permissions": ["admin", "Contributor", "Storage Blob Data Owner"],
                "mfa_enabled": False,
                "created_at": (now - timedelta(days=400)).isoformat(),
                "last_used": (now - timedelta(days=150)).isoformat(),
                "metadata": {"environment": env},
            },
        ]
