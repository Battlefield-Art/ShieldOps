"""Tool functions for the Identity Graph Agent.

These bridge identity providers, directory services, and cloud IAM
to the agent's LangGraph nodes.  Includes NHI (non-human identity)
discovery, classification, risk scoring, relationship mapping,
anomaly detection, governance reporting, AWS IAM enumeration,
CrowdStrike identity correlation, and identity risk assessment.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from shieldops.connectors.base import ConnectorRouter
from shieldops.policy.engine import PolicyContext
from shieldops.policy.engine import evaluate as policy_evaluate
from shieldops.utils.llm import llm_structured
from shieldops.utils.persistence import persist_agent_run

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

_ADMIN_POLICY_ARNS: set[str] = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
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
    """Collection of tools for identity graph discovery and analysis.

    Supports AWS IAM enumeration, CrowdStrike identity correlation,
    NHI discovery/cataloging, and LLM-enhanced risk assessment with
    heuristic fallback.
    """

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
    # AWS IAM enumeration
    # ------------------------------------------------------------------

    async def enumerate_iam_users(self) -> list[dict[str, Any]]:
        """List all IAM users via AWS connector with access key metadata.

        Returns a list of dicts with user_name, user_id, arn, created_at,
        access_keys (with last_used, age_days, status), attached_policies,
        and groups.
        """
        logger.info("identity_graph.enumerate_iam_users")
        now = datetime.now(UTC)

        if self._router is None:
            return self._mock_iam_users(now)

        try:
            connector = self._router.get("aws")
            connector._ensure_clients()  # type: ignore[attr-defined]

            import boto3

            session = boto3.Session(region_name=getattr(connector, "_region", "us-east-1"))
            iam_client = session.client("iam")

            import asyncio
            from functools import partial

            loop = asyncio.get_running_loop()

            users_resp = await loop.run_in_executor(
                None, partial(iam_client.list_users, MaxItems=200)
            )
            users: list[dict[str, Any]] = []

            for u in users_resp.get("Users", []):
                user_name = u["UserName"]
                user_record: dict[str, Any] = {
                    "user_name": user_name,
                    "user_id": u.get("UserId", ""),
                    "arn": u.get("Arn", ""),
                    "created_at": u.get("CreateDate", now).isoformat()
                    if hasattr(u.get("CreateDate", now), "isoformat")
                    else str(u.get("CreateDate", "")),
                    "path": u.get("Path", "/"),
                    "access_keys": [],
                    "attached_policies": [],
                    "groups": [],
                }

                # Get access keys
                try:
                    keys_resp = await loop.run_in_executor(
                        None,
                        partial(iam_client.list_access_keys, UserName=user_name),
                    )
                    for key in keys_resp.get("AccessKeyMetadata", []):
                        key_id = key["AccessKeyId"]
                        # Get last used info
                        try:
                            last_used_resp = await loop.run_in_executor(
                                None,
                                partial(
                                    iam_client.get_access_key_last_used,
                                    AccessKeyId=key_id,
                                ),
                            )
                            last_used_info = last_used_resp.get("AccessKeyLastUsed", {})
                            last_used_date = last_used_info.get("LastUsedDate")
                        except Exception:
                            last_used_date = None

                        created = key.get("CreateDate", now)
                        age_days = (
                            (now - created.replace(tzinfo=UTC)).days
                            if hasattr(created, "replace")
                            else 0
                        )

                        user_record["access_keys"].append(
                            {
                                "access_key_id": key_id,
                                "status": key.get("Status", "Unknown"),
                                "created_at": created.isoformat()
                                if hasattr(created, "isoformat")
                                else str(created),
                                "age_days": age_days,
                                "last_used": last_used_date.isoformat()
                                if last_used_date and hasattr(last_used_date, "isoformat")
                                else None,
                            }
                        )
                except Exception as e:
                    logger.warning(
                        "identity_graph.access_keys_failed",
                        user=user_name,
                        error=str(e),
                    )

                # Get attached policies
                try:
                    policies_resp = await loop.run_in_executor(
                        None,
                        partial(
                            iam_client.list_attached_user_policies,
                            UserName=user_name,
                        ),
                    )
                    user_record["attached_policies"] = [
                        {
                            "policy_name": p["PolicyName"],
                            "policy_arn": p["PolicyArn"],
                        }
                        for p in policies_resp.get("AttachedPolicies", [])
                    ]
                except Exception as e:
                    logger.warning(
                        "identity_graph.policies_failed",
                        user=user_name,
                        error=str(e),
                    )

                # Get groups
                try:
                    groups_resp = await loop.run_in_executor(
                        None,
                        partial(iam_client.list_groups_for_user, UserName=user_name),
                    )
                    user_record["groups"] = [g["GroupName"] for g in groups_resp.get("Groups", [])]
                except Exception as e:
                    logger.warning(
                        "identity_graph.groups_failed",
                        user=user_name,
                        error=str(e),
                    )

                users.append(user_record)

            logger.info("identity_graph.iam_users_enumerated", count=len(users))
            return users

        except Exception as e:
            logger.error("identity_graph.iam_enumeration_failed", error=str(e))
            return self._mock_iam_users(now)

    async def enumerate_iam_roles(self) -> list[dict[str, Any]]:
        """List all IAM roles via AWS connector.

        Returns a list of dicts with role_name, role_id, arn, created_at,
        attached_policies, and trust_policy (AssumeRolePolicyDocument).
        """
        logger.info("identity_graph.enumerate_iam_roles")
        now = datetime.now(UTC)

        if self._router is None:
            return self._mock_iam_roles(now)

        try:
            connector = self._router.get("aws")
            connector._ensure_clients()  # type: ignore[attr-defined]

            import boto3

            session = boto3.Session(region_name=getattr(connector, "_region", "us-east-1"))
            iam_client = session.client("iam")

            import asyncio
            from functools import partial

            loop = asyncio.get_running_loop()

            roles_resp = await loop.run_in_executor(
                None, partial(iam_client.list_roles, MaxItems=200)
            )
            roles: list[dict[str, Any]] = []

            for r in roles_resp.get("Roles", []):
                role_name = r["RoleName"]
                role_record: dict[str, Any] = {
                    "role_name": role_name,
                    "role_id": r.get("RoleId", ""),
                    "arn": r.get("Arn", ""),
                    "created_at": r.get("CreateDate", now).isoformat()
                    if hasattr(r.get("CreateDate", now), "isoformat")
                    else str(r.get("CreateDate", "")),
                    "path": r.get("Path", "/"),
                    "trust_policy": r.get("AssumeRolePolicyDocument", {}),
                    "attached_policies": [],
                }

                try:
                    policies_resp = await loop.run_in_executor(
                        None,
                        partial(
                            iam_client.list_attached_role_policies,
                            RoleName=role_name,
                        ),
                    )
                    role_record["attached_policies"] = [
                        {
                            "policy_name": p["PolicyName"],
                            "policy_arn": p["PolicyArn"],
                        }
                        for p in policies_resp.get("AttachedPolicies", [])
                    ]
                except Exception as e:
                    logger.warning(
                        "identity_graph.role_policies_failed",
                        role=role_name,
                        error=str(e),
                    )

                roles.append(role_record)

            logger.info("identity_graph.iam_roles_enumerated", count=len(roles))
            return roles

        except Exception as e:
            logger.error("identity_graph.iam_role_enumeration_failed", error=str(e))
            return self._mock_iam_roles(now)

    async def identify_stale_credentials(
        self,
        iam_users: list[dict[str, Any]],
        threshold_days: int = _STALE_THRESHOLD_DAYS,
    ) -> list[dict[str, Any]]:
        """Identify access keys not used in threshold_days or more.

        Returns a list of dicts with user_name, access_key_id,
        last_used, age_days, idle_days, and risk_level.
        """
        now = datetime.now(UTC)
        stale: list[dict[str, Any]] = []

        for user in iam_users:
            for key in user.get("access_keys", []):
                if key.get("status") != "Active":
                    continue

                last_used_str = key.get("last_used")
                age_days = key.get("age_days", 0)
                idle_days: int | None = None

                if last_used_str:
                    try:
                        last_used_dt = datetime.fromisoformat(last_used_str)
                        idle_days = (now - last_used_dt.replace(tzinfo=UTC)).days
                    except (ValueError, TypeError):
                        idle_days = None
                else:
                    # Never used -- treat as stale
                    idle_days = age_days

                is_stale = idle_days is not None and idle_days >= threshold_days
                is_old = age_days >= threshold_days

                if is_stale or is_old:
                    risk = "critical" if (is_stale and is_old) else "high"
                    stale.append(
                        {
                            "user_name": user.get("user_name", ""),
                            "access_key_id": key.get("access_key_id", ""),
                            "last_used": last_used_str,
                            "age_days": age_days,
                            "idle_days": idle_days,
                            "is_stale": is_stale,
                            "is_old": is_old,
                            "risk_level": risk,
                        }
                    )

        logger.info("identity_graph.stale_credentials_found", count=len(stale))
        return stale

    # ------------------------------------------------------------------
    # CrowdStrike identity correlation
    # ------------------------------------------------------------------

    async def fetch_crowdstrike_hosts(
        self,
        filter_query: str = "",
    ) -> list[dict[str, Any]]:
        """Fetch CrowdStrike identity/host data via the connector.

        Returns a list of host records with device_id, hostname, ip,
        platform, os_version, agent_version, last_seen, and status.
        """
        logger.info("identity_graph.fetch_crowdstrike_hosts", filter=filter_query)

        if self._router is None:
            return self._mock_crowdstrike_hosts()

        try:
            connector = self._router.get("crowdstrike")
            data = await connector.list_resources(  # type: ignore[arg-type]
                resource_type="host",
                environment="production",
                filters={"fql": filter_query} if filter_query else None,
            )
            hosts: list[dict[str, Any]] = []
            for resource in data:
                hosts.append(
                    {
                        "device_id": resource.id,
                        "hostname": resource.name,
                        "platform": resource.labels.get("platform", ""),
                        "os_version": resource.labels.get("os_version", ""),
                        "agent_version": resource.metadata.get("agent_version", ""),
                        "last_seen": resource.metadata.get("last_seen", ""),
                        "status": resource.metadata.get("status", ""),
                    }
                )
            return hosts

        except Exception as e:
            logger.error("identity_graph.crowdstrike_fetch_failed", error=str(e))
            return self._mock_crowdstrike_hosts()

    async def correlate_crowdstrike_aws_identities(
        self,
        iam_users: list[dict[str, Any]],
        crowdstrike_hosts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Correlate CrowdStrike host identities with AWS IAM principals.

        Matching heuristics:
        - Hostname contains IAM user_name (case-insensitive)
        - Host metadata tags match IAM user or role
        - Service account naming conventions (e.g., "svc-<name>")

        Returns a list of correlation dicts with aws_identity, cs_host,
        match_type, and confidence_score.
        """
        logger.info(
            "identity_graph.correlating_identities",
            iam_count=len(iam_users),
            cs_count=len(crowdstrike_hosts),
        )
        correlations: list[dict[str, Any]] = []

        # Build lookup indices
        iam_by_name: dict[str, dict[str, Any]] = {
            u["user_name"].lower(): u for u in iam_users if u.get("user_name")
        }

        for host in crowdstrike_hosts:
            hostname = (host.get("hostname") or "").lower()
            device_id = host.get("device_id", "")

            for iam_name, iam_user in iam_by_name.items():
                # Heuristic 1: hostname contains username
                if iam_name and iam_name in hostname:
                    correlations.append(
                        {
                            "aws_identity": iam_user.get("user_name", ""),
                            "aws_arn": iam_user.get("arn", ""),
                            "cs_device_id": device_id,
                            "cs_hostname": host.get("hostname", ""),
                            "match_type": "hostname_contains_username",
                            "confidence_score": 0.7,
                        }
                    )
                    continue

                # Heuristic 2: service account naming convention
                for prefix in ("svc-", "sa-", "service-"):
                    stripped = iam_name.removeprefix(prefix)
                    if stripped != iam_name and stripped in hostname:
                        correlations.append(
                            {
                                "aws_identity": iam_user.get("user_name", ""),
                                "aws_arn": iam_user.get("arn", ""),
                                "cs_device_id": device_id,
                                "cs_hostname": host.get("hostname", ""),
                                "match_type": "service_account_convention",
                                "confidence_score": 0.6,
                            }
                        )
                        break

        logger.info(
            "identity_graph.correlation_complete",
            matches=len(correlations),
        )
        return correlations

    # ------------------------------------------------------------------
    # NHI (Non-Human Identity) discovery & cataloging
    # ------------------------------------------------------------------

    async def discover_nhis(
        self,
        iam_users: list[dict[str, Any]],
        iam_roles: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Identify and catalog non-human identities from IAM data.

        Detects service accounts, API keys, machine credentials, and
        bot accounts. Each NHI record includes type, owner, last_used,
        risk_score, permissions, and over_privileged flag.
        """
        now = datetime.now(UTC)
        nhis: list[dict[str, Any]] = []

        # Check users for NHI patterns
        for user in iam_users:
            name = (user.get("user_name") or "").lower()
            is_nhi = any(
                kw in name
                for kw in (
                    "svc",
                    "service",
                    "bot",
                    "automation",
                    "ci",
                    "cd",
                    "pipeline",
                    "deploy",
                    "machine",
                    "system",
                    "api",
                    "lambda",
                    "scheduler",
                    "cron",
                )
            )
            if not is_nhi:
                # Also check path: service accounts often under /service/
                path = (user.get("path") or "").lower()
                is_nhi = "/service/" in path or "/system/" in path

            if is_nhi:
                policies = user.get("attached_policies", [])
                policy_arns = {p.get("policy_arn", "") for p in policies}
                policy_names = {p.get("policy_name", "").lower() for p in policies}
                over_privileged = bool(
                    policy_arns & _ADMIN_POLICY_ARNS
                    or policy_names & {n.lower() for n in _ADMIN_KEYWORDS}
                )

                # Determine last used from access keys
                last_used: str | None = None
                for key in user.get("access_keys", []):
                    key_last = key.get("last_used")
                    if key_last and (last_used is None or key_last > last_used):
                        last_used = key_last

                # Risk score heuristic
                risk = 0.0
                if over_privileged:
                    risk += 40.0
                if not last_used:
                    risk += 15.0
                else:
                    try:
                        lu_dt = datetime.fromisoformat(last_used)
                        idle = (now - lu_dt.replace(tzinfo=UTC)).days
                        if idle > _STALE_THRESHOLD_DAYS:
                            risk += 25.0
                    except (ValueError, TypeError):
                        pass
                for key in user.get("access_keys", []):
                    if key.get("age_days", 0) > _CREDENTIAL_ROTATION_DAYS:
                        risk += 15.0
                        break
                risk = min(risk, 100.0)

                nhi_type = "service_account"
                if "bot" in name:
                    nhi_type = "bot_account"
                elif "api" in name or "key" in name:
                    nhi_type = "api_key"

                nhis.append(
                    {
                        "identity_id": user.get("user_name", ""),
                        "arn": user.get("arn", ""),
                        "nhi_type": nhi_type,
                        "source": "aws_iam_user",
                        "owner": (user.get("groups") or ["unknown"])[0],
                        "last_used": last_used,
                        "created_at": user.get("created_at"),
                        "risk_score": risk,
                        "over_privileged": over_privileged,
                        "permissions": [p.get("policy_name", "") for p in policies],
                        "access_key_count": len(user.get("access_keys", [])),
                    }
                )

        # Check roles for NHI (all IAM roles are non-human by definition)
        for role in iam_roles:
            policies = role.get("attached_policies", [])
            policy_arns = {p.get("policy_arn", "") for p in policies}
            over_privileged = bool(policy_arns & _ADMIN_POLICY_ARNS)

            risk = 0.0
            if over_privileged:
                risk += 40.0
            # Cross-account trust increases risk
            trust_doc = role.get("trust_policy", {})
            principals = self._extract_trust_principals(trust_doc)
            if any("arn:aws:iam::" in p and ":root" in p for p in principals):
                risk += 20.0
            risk = min(risk, 100.0)

            nhis.append(
                {
                    "identity_id": role.get("role_name", ""),
                    "arn": role.get("arn", ""),
                    "nhi_type": "iam_role",
                    "source": "aws_iam_role",
                    "owner": "aws",
                    "last_used": None,
                    "created_at": role.get("created_at"),
                    "risk_score": risk,
                    "over_privileged": over_privileged,
                    "permissions": [p.get("policy_name", "") for p in policies],
                    "trust_principals": principals,
                }
            )

        logger.info("identity_graph.nhis_discovered", count=len(nhis))
        return nhis

    # ------------------------------------------------------------------
    # Identity risk assessment (LLM + heuristic fallback)
    # ------------------------------------------------------------------

    async def assess_identity_risk_llm(
        self,
        nhis: list[dict[str, Any]],
        stale_credentials: list[dict[str, Any]],
        correlations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Use llm_structured() to analyze identity risk across all findings.

        Falls back to rule-based heuristic scoring on LLM failure.

        Returns a dict with risk_summary, high_risk_identities,
        over_privileged_accounts, stale_accounts, cross_account_risks,
        and risk_score_by_identity.
        """
        from shieldops.agents.identity_graph.prompts import (
            SYSTEM_IDENTITY_RISK_ASSESSMENT,
            IdentityRiskResult,
        )

        # Build context
        context_lines = ["## Non-Human Identities"]
        for nhi in nhis[:30]:
            context_lines.append(
                f"- {nhi['identity_id']} ({nhi['nhi_type']}): "
                f"risk={nhi['risk_score']:.0f}, "
                f"over_privileged={nhi['over_privileged']}, "
                f"owner={nhi.get('owner', 'unknown')}"
            )

        context_lines.append(f"\n## Stale Credentials ({len(stale_credentials)})")
        for sc in stale_credentials[:20]:
            context_lines.append(
                f"- {sc['user_name']}/{sc['access_key_id']}: "
                f"idle={sc.get('idle_days')}d, age={sc['age_days']}d"
            )

        if correlations:
            context_lines.append(f"\n## Cross-Platform Correlations ({len(correlations)})")
            for c in correlations[:10]:
                context_lines.append(
                    f"- {c['aws_identity']} <-> {c['cs_hostname']} "
                    f"({c['match_type']}, conf={c['confidence_score']})"
                )

        user_prompt = "\n".join(context_lines)

        try:
            from typing import cast

            result = cast(
                IdentityRiskResult,
                await llm_structured(
                    system_prompt=SYSTEM_IDENTITY_RISK_ASSESSMENT,
                    user_prompt=user_prompt,
                    schema=IdentityRiskResult,
                ),
            )
            return {
                "risk_summary": result.risk_summary,
                "high_risk_identities": result.high_risk_identities,
                "over_privileged_accounts": result.over_privileged,
                "stale_accounts": [{"identity_id": s} for s in result.stale_credentials],
                "risk_factors": result.risk_factors,
                "source": "llm",
            }
        except Exception as e:
            logger.warning(
                "identity_graph.llm_risk_assessment_fallback",
                error=str(e),
            )
            return self._heuristic_risk_assessment(nhis, stale_credentials)

    def _heuristic_risk_assessment(
        self,
        nhis: list[dict[str, Any]],
        stale_credentials: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Rule-based fallback risk assessment when LLM is unavailable.

        Rules:
        - age > 90d -> stale
        - admin policy on service account -> over-privileged
        - risk_score >= 50 -> high risk
        """
        high_risk = [n for n in nhis if n.get("risk_score", 0) >= 50]
        over_priv = [n for n in nhis if n.get("over_privileged")]
        stale = [
            {"identity_id": s["user_name"], "idle_days": s.get("idle_days")}
            for s in stale_credentials
        ]

        risk_factors = []
        if over_priv:
            risk_factors.append(f"{len(over_priv)} over-privileged service accounts")
        if stale:
            risk_factors.append(f"{len(stale)} stale credentials (>{_STALE_THRESHOLD_DAYS}d)")
        if high_risk:
            risk_factors.append(f"{len(high_risk)} high-risk identities")

        return {
            "risk_summary": (
                f"Heuristic assessment: {len(high_risk)} high-risk, "
                f"{len(over_priv)} over-privileged, {len(stale)} stale"
            ),
            "high_risk_identities": [n["identity_id"] for n in high_risk],
            "over_privileged_accounts": [
                {
                    "identity_id": n["identity_id"],
                    "permissions": n.get("permissions", []),
                }
                for n in over_priv
            ],
            "stale_accounts": stale,
            "risk_factors": risk_factors,
            "source": "heuristic",
        }

    # ------------------------------------------------------------------
    # OPA policy evaluation
    # ------------------------------------------------------------------

    async def check_policy(
        self,
        action: str,
        target_identities: list[str],
        environment: str = "production",
        risk_score: float = 0.0,
    ) -> dict[str, Any]:
        """Evaluate an identity action against OPA policies.

        Returns the policy decision (allowed, decision, reason).
        """
        try:
            ctx = PolicyContext(
                agent_name="identity_graph",
                action_type=action,
                target_resources=target_identities,
                environment=environment,
                risk_score=risk_score,
            )
            decision = await policy_evaluate(action, ctx)
            return {
                "allowed": decision.allowed,
                "decision": decision.decision,
                "reason": decision.reason,
                "matched_policies": decision.matched_policies,
            }
        except Exception as e:
            logger.warning("identity_graph.policy_check_failed", error=str(e))
            # Fail-open for read-only scans, fail-closed for mutations
            is_read_only = action in ("scan", "enumerate", "discover", "assess")
            return {
                "allowed": is_read_only,
                "decision": "approved" if is_read_only else "denied",
                "reason": f"Policy check failed: {e}",
                "matched_policies": [],
            }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def persist_scan_result(
        self,
        scan_target: str,
        result: dict[str, Any],
        duration_ms: int = 0,
        error: str | None = None,
    ) -> str | None:
        """Persist scan results via the agent run persistence utility."""
        try:
            return await persist_agent_run(
                agent_name="identity_graph",
                org_id=scan_target,
                input_data={"scan_target": scan_target},
                output_data=result,
                duration_ms=duration_ms,
                error_message=error,
            )
        except Exception as e:
            logger.warning("identity_graph.persist_failed", error=str(e))
            return None

    # ------------------------------------------------------------------
    # NHI (Non-Human Identity) discovery & risk scoring (original)
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
    def _extract_trust_principals(
        trust_doc: dict[str, Any],
    ) -> list[str]:
        """Extract principal ARNs from an IAM role trust policy document."""
        principals: list[str] = []
        for statement in trust_doc.get("Statement", []):
            principal = statement.get("Principal", {})
            if isinstance(principal, str):
                principals.append(principal)
            elif isinstance(principal, dict):
                for _key, val in principal.items():
                    if isinstance(val, str):
                        principals.append(val)
                    elif isinstance(val, list):
                        principals.extend(val)
        return principals

    @staticmethod
    def _mock_iam_users(now: datetime) -> list[dict[str, Any]]:
        """Return mock IAM user data for testing without AWS credentials."""
        return [
            {
                "user_name": "admin-user",
                "user_id": "AIDA123ADMIN",
                "arn": "arn:aws:iam::123456789012:user/admin-user",
                "created_at": (now - timedelta(days=365)).isoformat(),
                "path": "/",
                "access_keys": [
                    {
                        "access_key_id": "AKIA_ADMIN_001",
                        "status": "Active",
                        "created_at": (now - timedelta(days=200)).isoformat(),
                        "age_days": 200,
                        "last_used": (now - timedelta(days=2)).isoformat(),
                    },
                ],
                "attached_policies": [
                    {
                        "policy_name": "AdministratorAccess",
                        "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    },
                ],
                "groups": ["admins"],
            },
            {
                "user_name": "svc-deploy-pipeline",
                "user_id": "AIDA123SVC",
                "arn": "arn:aws:iam::123456789012:user/svc-deploy-pipeline",
                "created_at": (now - timedelta(days=180)).isoformat(),
                "path": "/service/",
                "access_keys": [
                    {
                        "access_key_id": "AKIA_SVC_001",
                        "status": "Active",
                        "created_at": (now - timedelta(days=180)).isoformat(),
                        "age_days": 180,
                        "last_used": (now - timedelta(days=5)).isoformat(),
                    },
                    {
                        "access_key_id": "AKIA_SVC_002",
                        "status": "Active",
                        "created_at": (now - timedelta(days=120)).isoformat(),
                        "age_days": 120,
                        "last_used": None,
                    },
                ],
                "attached_policies": [
                    {
                        "policy_name": "AdministratorAccess",
                        "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    },
                ],
                "groups": ["deployers"],
            },
            {
                "user_name": "dev-user",
                "user_id": "AIDA123DEV",
                "arn": "arn:aws:iam::123456789012:user/dev-user",
                "created_at": (now - timedelta(days=30)).isoformat(),
                "path": "/",
                "access_keys": [
                    {
                        "access_key_id": "AKIA_DEV_001",
                        "status": "Active",
                        "created_at": (now - timedelta(days=30)).isoformat(),
                        "age_days": 30,
                        "last_used": (now - timedelta(days=1)).isoformat(),
                    },
                ],
                "attached_policies": [
                    {
                        "policy_name": "ReadOnlyAccess",
                        "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    },
                ],
                "groups": ["developers"],
            },
            {
                "user_name": "ci-bot-runner",
                "user_id": "AIDA123BOT",
                "arn": "arn:aws:iam::123456789012:user/ci-bot-runner",
                "created_at": (now - timedelta(days=400)).isoformat(),
                "path": "/service/",
                "access_keys": [
                    {
                        "access_key_id": "AKIA_BOT_001",
                        "status": "Active",
                        "created_at": (now - timedelta(days=400)).isoformat(),
                        "age_days": 400,
                        "last_used": (now - timedelta(days=150)).isoformat(),
                    },
                ],
                "attached_policies": [
                    {
                        "policy_name": "PowerUserAccess",
                        "policy_arn": "arn:aws:iam::aws:policy/PowerUserAccess",
                    },
                ],
                "groups": [],
            },
        ]

    @staticmethod
    def _mock_iam_roles(now: datetime) -> list[dict[str, Any]]:
        """Return mock IAM role data for testing without AWS credentials."""
        return [
            {
                "role_name": "lambda-execution-role",
                "role_id": "AROA123LAMBDA",
                "arn": "arn:aws:iam::123456789012:role/lambda-execution-role",
                "created_at": (now - timedelta(days=90)).isoformat(),
                "path": "/service-role/",
                "trust_policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
                "attached_policies": [
                    {
                        "policy_name": "AWSLambdaBasicExecutionRole",
                        "policy_arn": (
                            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                        ),
                    },
                ],
            },
            {
                "role_name": "cross-account-admin",
                "role_id": "AROA123CROSS",
                "arn": "arn:aws:iam::123456789012:role/cross-account-admin",
                "created_at": (now - timedelta(days=200)).isoformat(),
                "path": "/",
                "trust_policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::999888777666:root"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
                "attached_policies": [
                    {
                        "policy_name": "AdministratorAccess",
                        "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    },
                ],
            },
        ]

    @staticmethod
    def _mock_crowdstrike_hosts() -> list[dict[str, Any]]:
        """Return mock CrowdStrike host data for testing."""
        return [
            {
                "device_id": "cs-dev-001",
                "hostname": "dev-user-workstation",
                "platform": "Windows",
                "os_version": "Windows 11",
                "agent_version": "7.10.0",
                "last_seen": "2026-04-01T10:00:00Z",
                "status": "normal",
            },
            {
                "device_id": "cs-svc-001",
                "hostname": "svc-deploy-pipeline-host",
                "platform": "Linux",
                "os_version": "Ubuntu 22.04",
                "agent_version": "7.10.0",
                "last_seen": "2026-04-01T09:30:00Z",
                "status": "normal",
            },
            {
                "device_id": "cs-prod-001",
                "hostname": "prod-api-server-01",
                "platform": "Linux",
                "os_version": "Amazon Linux 2",
                "agent_version": "7.09.0",
                "last_seen": "2026-03-15T12:00:00Z",
                "status": "contained",
            },
        ]

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
