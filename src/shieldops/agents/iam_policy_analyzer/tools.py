"""IAM Policy Analyzer Agent — Tool functions for IAM policy collection and analysis."""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from typing import Any

import structlog

from .models import (
    CloudProvider,
    IAMPolicy,
    OverprivilegeAlert,
    PermissionAnalysis,
    PolicyRecommendation,
    RiskLevel,
    UnusedPermission,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Realistic IAM policy templates per provider
# ---------------------------------------------------------------------------
_AWS_ROLES: list[dict[str, Any]] = [
    {
        "principal_name": "prod-lambda-execution-role",
        "principal_type": "role",
        "policy_name": "LambdaFullAccess",
        "actions": [
            "lambda:*",
            "s3:GetObject",
            "s3:PutObject",
            "dynamodb:*",
            "logs:CreateLogGroup",
            "logs:PutLogEvents",
            "sqs:SendMessage",
            "sqs:ReceiveMessage",
        ],
        "resources": ["*"],
        "is_aws_managed": False,
    },
    {
        "principal_name": "ci-cd-deploy-role",
        "principal_type": "role",
        "policy_name": "AdministratorAccess",
        "actions": ["*"],
        "resources": ["*"],
        "is_aws_managed": True,
    },
    {
        "principal_name": "data-pipeline-role",
        "principal_type": "role",
        "policy_name": "DataPipelinePolicy",
        "actions": [
            "s3:*",
            "glue:*",
            "athena:*",
            "redshift:*",
            "kms:Decrypt",
            "kms:GenerateDataKey",
            "iam:PassRole",
        ],
        "resources": ["*"],
        "is_aws_managed": False,
    },
    {
        "principal_name": "readonly-audit-role",
        "principal_type": "role",
        "policy_name": "ReadOnlyAccess",
        "actions": [
            "s3:GetObject",
            "s3:ListBucket",
            "ec2:Describe*",
            "rds:Describe*",
            "cloudwatch:GetMetricData",
        ],
        "resources": ["*"],
        "is_aws_managed": True,
    },
    {
        "principal_name": "dev-user-alice",
        "principal_type": "user",
        "policy_name": "DeveloperPolicy",
        "actions": [
            "ec2:*",
            "s3:*",
            "lambda:*",
            "cloudformation:*",
            "iam:CreateRole",
            "iam:AttachRolePolicy",
            "iam:PassRole",
        ],
        "resources": ["*"],
        "is_aws_managed": False,
    },
    {
        "principal_name": "eks-node-role",
        "principal_type": "role",
        "policy_name": "EKSNodePolicy",
        "actions": [
            "ec2:Describe*",
            "ecr:GetDownloadUrlForLayer",
            "ecr:BatchGetImage",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
        ],
        "resources": ["*"],
        "is_aws_managed": True,
    },
]

_GCP_SERVICE_ACCOUNTS: list[dict[str, Any]] = [
    {
        "principal_name": "ml-training-sa@proj.iam",
        "principal_type": "service_account",
        "policy_name": "roles/editor",
        "actions": [
            "storage.objects.*",
            "bigquery.*",
            "compute.instances.*",
            "aiplatform.*",
            "iam.serviceAccounts.actAs",
        ],
        "resources": ["projects/ml-prod-123"],
        "is_aws_managed": False,
    },
    {
        "principal_name": "terraform-sa@proj.iam",
        "principal_type": "service_account",
        "policy_name": "roles/owner",
        "actions": ["*"],
        "resources": ["projects/infra-prod-456"],
        "is_aws_managed": False,
    },
    {
        "principal_name": "cloud-function-sa@proj.iam",
        "principal_type": "service_account",
        "policy_name": "CloudFunctionInvoker",
        "actions": [
            "cloudfunctions.functions.invoke",
            "pubsub.topics.publish",
            "storage.objects.get",
            "logging.logEntries.create",
        ],
        "resources": [
            "projects/app-prod-789/topics/events",
        ],
        "is_aws_managed": False,
    },
    {
        "principal_name": "gke-workload-sa@proj.iam",
        "principal_type": "service_account",
        "policy_name": "GKEWorkloadIdentity",
        "actions": [
            "container.clusters.get",
            "storage.objects.get",
            "secretmanager.versions.access",
            "monitoring.timeSeries.create",
        ],
        "resources": [
            "projects/platform-prod-101",
        ],
        "is_aws_managed": False,
    },
]

_AZURE_PRINCIPALS: list[dict[str, Any]] = [
    {
        "principal_name": "aks-cluster-sp",
        "principal_type": "service_principal",
        "policy_name": "Contributor",
        "actions": ["*"],
        "resources": [
            "/subscriptions/sub-001/resourceGroups/prod-rg",
        ],
        "is_aws_managed": False,
    },
    {
        "principal_name": "devops-pipeline-sp",
        "principal_type": "service_principal",
        "policy_name": "Owner",
        "actions": ["*"],
        "resources": ["/subscriptions/sub-001"],
        "is_aws_managed": False,
    },
    {
        "principal_name": "monitoring-reader-sp",
        "principal_type": "service_principal",
        "policy_name": "MonitoringReader",
        "actions": [
            "Microsoft.Insights/metrics/read",
            "Microsoft.Insights/logs/read",
            "Microsoft.Resources/subscriptions/read",
        ],
        "resources": ["/subscriptions/sub-001"],
        "is_aws_managed": False,
    },
    {
        "principal_name": "backup-operator-sp",
        "principal_type": "service_principal",
        "policy_name": "BackupContributor",
        "actions": [
            "Microsoft.RecoveryServices/vaults/*",
            "Microsoft.Storage/storageAccounts/read",
            "Microsoft.Compute/virtualMachines/read",
        ],
        "resources": [
            "/subscriptions/sub-001/resourceGroups/backup-rg",
        ],
        "is_aws_managed": False,
    },
]

# Sensitive actions that indicate elevated risk
_SENSITIVE_ACTIONS: dict[str, list[str]] = {
    "aws": [
        "iam:*",
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:PassRole",
        "iam:CreateUser",
        "iam:PutUserPolicy",
        "sts:AssumeRole",
        "kms:Decrypt",
        "organizations:*",
        "s3:DeleteBucket",
    ],
    "gcp": [
        "iam.serviceAccounts.actAs",
        "iam.roles.create",
        "iam.serviceAccountKeys.create",
        "resourcemanager.projects.setIamPolicy",
        "compute.instances.setServiceAccount",
    ],
    "azure": [
        "Microsoft.Authorization/roleAssignments/*",
        "Microsoft.Authorization/roleDefinitions/*",
        "Microsoft.KeyVault/vaults/secrets/*",
        "Microsoft.Compute/virtualMachines/delete",
    ],
}

# Usage data — days since last use per action
_USAGE_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "frequently_used": [
        {"days_inactive": 0, "last_used": "2026-03-30"},
        {"days_inactive": 1, "last_used": "2026-03-29"},
        {"days_inactive": 3, "last_used": "2026-03-27"},
    ],
    "occasionally_used": [
        {"days_inactive": 30, "last_used": "2026-02-28"},
        {"days_inactive": 45, "last_used": "2026-02-13"},
        {"days_inactive": 60, "last_used": "2026-01-29"},
    ],
    "stale": [
        {"days_inactive": 120, "last_used": "2025-11-30"},
        {"days_inactive": 180, "last_used": "2025-09-30"},
        {"days_inactive": 270, "last_used": "2025-07-03"},
    ],
    "never_used": [
        {"days_inactive": 365, "last_used": "never"},
    ],
}


def _policy_hash(
    provider: str,
    principal: str,
    idx: int,
) -> str:
    """Deterministic policy id."""
    raw = f"{provider}-{principal}-{idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class IAMPolicyAnalyzerToolkit:
    """Tools for multi-cloud IAM policy collection and analysis."""

    def __init__(
        self,
        iam_clients: Any | None = None,
        usage_tracker: Any | None = None,
    ) -> None:
        self._iam_clients = iam_clients
        self._usage_tracker = usage_tracker

    # ---------------------------------------------------------------
    # 1. Collect IAM policies
    # ---------------------------------------------------------------
    async def collect_policies(
        self,
        tenant_id: str,
        providers: list[str],
    ) -> list[IAMPolicy]:
        """Collect IAM policies across requested cloud providers.

        Uses live IAM clients if available; otherwise returns
        realistic mock data for demonstration and testing.
        """
        logger.info(
            "iam_policy_analyzer.collect_policies",
            tenant_id=tenant_id,
            providers=providers,
        )

        if self._iam_clients is not None:
            try:
                raw = await self._iam_clients.list_policies(
                    tenant_id=tenant_id,
                    providers=providers,
                )
                return [IAMPolicy(**p) for p in raw]
            except Exception:
                logger.exception(
                    "iam_policy_analyzer.collect.client_error",
                )

        # Mock fallback
        policies: list[IAMPolicy] = []
        provider_templates: dict[str, list[dict[str, Any]]] = {
            "aws": _AWS_ROLES,
            "gcp": _GCP_SERVICE_ACCOUNTS,
            "azure": _AZURE_PRINCIPALS,
        }

        for provider_key in providers:
            templates = provider_templates.get(provider_key, [])
            for idx, tpl in enumerate(templates):
                pid = _policy_hash(
                    provider_key,
                    tpl["principal_name"],
                    idx,
                )
                policies.append(
                    IAMPolicy(
                        id=pid,
                        provider=CloudProvider(provider_key),
                        principal_type=tpl["principal_type"],
                        principal_name=tpl["principal_name"],
                        policy_name=tpl["policy_name"],
                        policy_arn=f"arn:{provider_key}:{pid}",
                        actions=tpl["actions"],
                        resources=tpl["resources"],
                        effect="Allow",
                        is_aws_managed=tpl.get("is_aws_managed", False),
                        attached_at=time.time()
                        - random.randint(  # noqa: S311
                            86400, 86400 * 365
                        ),
                    )
                )

        logger.info(
            "iam_policy_analyzer.collect_policies.done",
            policy_count=len(policies),
        )
        return policies

    # ---------------------------------------------------------------
    # 2. Analyze permissions
    # ---------------------------------------------------------------
    async def analyze_permissions(
        self,
        policies: list[IAMPolicy],
    ) -> list[PermissionAnalysis]:
        """Analyze each policy for wildcard, admin, and sensitive actions."""
        logger.info(
            "iam_policy_analyzer.analyze_permissions",
            policy_count=len(policies),
        )

        analyses: list[PermissionAnalysis] = []
        for policy in policies:
            provider_key = policy.provider.value
            sensitive = _SENSITIVE_ACTIONS.get(provider_key, [])

            wildcard_count = sum(
                1 for a in policy.actions if a == "*" or a.endswith(":*") or a.endswith(".*")
            )
            admin_count = 1 if policy.actions == ["*"] else 0
            sensitive_count = sum(1 for a in policy.actions if a in sensitive)

            # Determine resource scope
            if policy.resources == ["*"]:
                scope = "wildcard"
            elif any("*" in r for r in policy.resources):
                scope = "account-wide"
            else:
                scope = "narrow"

            # Risk scoring
            base = 20.0
            base += wildcard_count * 15.0
            base += admin_count * 40.0
            base += sensitive_count * 10.0
            if scope == "wildcard":
                base += 15.0
            elif scope == "account-wide":
                base += 8.0
            risk = round(
                min(100.0, max(0.0, base)),
                1,
            )

            risk_level = self._score_to_risk(risk)

            analyses.append(
                PermissionAnalysis(
                    id=str(uuid.uuid4())[:8],
                    policy_id=policy.id,
                    principal_name=policy.principal_name,
                    provider=policy.provider,
                    total_actions=len(policy.actions),
                    wildcard_actions=wildcard_count,
                    admin_actions=admin_count,
                    sensitive_actions=sensitive_count,
                    resource_scope=scope,
                    risk_level=risk_level,
                    risk_score=risk,
                    notes=(
                        f"{policy.policy_name}: "
                        f"{wildcard_count} wildcard, "
                        f"{sensitive_count} sensitive actions"
                    ),
                )
            )

        logger.info(
            "iam_policy_analyzer.analyze_permissions.done",
            analysis_count=len(analyses),
        )
        return analyses

    # ---------------------------------------------------------------
    # 3. Detect over-privilege
    # ---------------------------------------------------------------
    async def detect_overprivilege(
        self,
        analyses: list[PermissionAnalysis],
        policies: list[IAMPolicy],
    ) -> list[OverprivilegeAlert]:
        """Flag principals with excessive permissions."""
        logger.info(
            "iam_policy_analyzer.detect_overprivilege",
            analysis_count=len(analyses),
        )

        alerts: list[OverprivilegeAlert] = []
        policy_map = {p.id: p for p in policies}

        for analysis in analyses:
            if analysis.risk_score < 50.0:
                continue

            policy = policy_map.get(analysis.policy_id)
            actions = policy.actions if policy else []

            # Classify over-privilege type
            if analysis.admin_actions > 0:
                op_type = "admin"
            elif analysis.wildcard_actions > 2:
                op_type = "wildcard"
            else:
                op_type = "cross-service"

            # Blast radius
            if analysis.resource_scope == "wildcard":
                blast = "org"
            elif analysis.resource_scope == "account-wide":
                blast = "account"
            else:
                blast = "single-resource"

            excessive = [a for a in actions if a == "*" or a.endswith(":*") or a.endswith(".*")]

            alerts.append(
                OverprivilegeAlert(
                    id=str(uuid.uuid4())[:8],
                    principal_name=analysis.principal_name,
                    provider=analysis.provider,
                    risk_level=analysis.risk_level,
                    overprivilege_type=op_type,
                    excessive_actions=excessive[:10],
                    blast_radius=blast,
                    description=(
                        f"{analysis.principal_name} has "
                        f"{op_type} over-privilege with "
                        f"{blast} blast radius "
                        f"(score: {analysis.risk_score})"
                    ),
                    cis_reference=self._cis_ref(
                        analysis.provider,
                        op_type,
                    ),
                )
            )

        logger.info(
            "iam_policy_analyzer.detect_overprivilege.done",
            alert_count=len(alerts),
        )
        return alerts

    # ---------------------------------------------------------------
    # 4. Find unused permissions
    # ---------------------------------------------------------------
    async def find_unused_permissions(
        self,
        policies: list[IAMPolicy],
    ) -> list[UnusedPermission]:
        """Identify permissions not exercised recently.

        Uses live usage tracker if available; otherwise
        simulates usage patterns for demonstration.
        """
        logger.info(
            "iam_policy_analyzer.find_unused_permissions",
            policy_count=len(policies),
        )

        if self._usage_tracker is not None:
            try:
                raw = await self._usage_tracker.get_unused(
                    policies=[p.model_dump() for p in policies],
                )
                return [UnusedPermission(**u) for u in raw]
            except Exception:
                logger.exception(
                    "iam_policy_analyzer.unused.tracker_error",
                )

        # Mock fallback
        unused: list[UnusedPermission] = []
        patterns = list(_USAGE_PATTERNS.values())

        for policy in policies:
            for action in policy.actions:
                # Simulate usage pattern
                pattern = random.choice(patterns)  # noqa: S311
                usage = random.choice(pattern)  # noqa: S311
                days = usage["days_inactive"]

                if days < 90:
                    continue  # Skip recently used

                risk = RiskLevel.LOW
                if days > 270:
                    risk = RiskLevel.HIGH
                elif days > 180:
                    risk = RiskLevel.MEDIUM

                # Elevate risk for sensitive unused actions
                provider_key = policy.provider.value
                sensitive = _SENSITIVE_ACTIONS.get(provider_key, [])
                if action in sensitive:
                    risk = RiskLevel.HIGH

                unused.append(
                    UnusedPermission(
                        id=str(uuid.uuid4())[:8],
                        principal_name=policy.principal_name,
                        provider=policy.provider,
                        action=action,
                        last_used=usage["last_used"],
                        days_inactive=days,
                        risk_level=risk,
                        recommendation=(
                            f"Remove {action} from {policy.principal_name} — unused for {days} days"
                        ),
                    )
                )

        logger.info(
            "iam_policy_analyzer.find_unused.done",
            unused_count=len(unused),
        )
        return unused

    # ---------------------------------------------------------------
    # 5. Generate recommendations
    # ---------------------------------------------------------------
    async def generate_recommendations(
        self,
        alerts: list[OverprivilegeAlert],
        unused: list[UnusedPermission],
        policies: list[IAMPolicy],
    ) -> list[PolicyRecommendation]:
        """Generate concrete policy-tightening recommendations."""
        logger.info(
            "iam_policy_analyzer.generate_recommendations",
            alert_count=len(alerts),
            unused_count=len(unused),
        )

        recs: list[PolicyRecommendation] = []
        policy_map = {p.principal_name: p for p in policies}

        # Recommendations from over-privilege alerts
        for alert in alerts:
            policy = policy_map.get(alert.principal_name)
            current = policy.policy_name if policy else "unknown"

            if alert.overprivilege_type == "admin":
                rec_type = "replace"
                suggested = "Create scoped policy with only required actions"
                effort = "high"
                reduction = 40.0
            elif alert.overprivilege_type == "wildcard":
                rec_type = "scope-down"
                suggested = "Replace wildcard actions with explicit action list"
                effort = "medium"
                reduction = 25.0
            else:
                rec_type = "scope-down"
                suggested = "Separate cross-service permissions into distinct roles"
                effort = "medium"
                reduction = 20.0

            recs.append(
                PolicyRecommendation(
                    id=str(uuid.uuid4())[:8],
                    principal_name=alert.principal_name,
                    provider=alert.provider,
                    recommendation_type=rec_type,
                    current_policy=current,
                    suggested_policy=suggested,
                    risk_reduction=reduction,
                    effort=effort,
                    description=(
                        f"{rec_type.title()} {current} for {alert.principal_name}: {suggested}"
                    ),
                    auto_applicable=(alert.overprivilege_type != "admin"),
                )
            )

        # Recommendations from unused permissions
        principal_unused: dict[str, list[str]] = {}
        for u in unused:
            principal_unused.setdefault(u.principal_name, []).append(u.action)

        for principal, actions in principal_unused.items():
            policy = policy_map.get(principal)
            current = policy.policy_name if policy else "unknown"
            provider = policy.provider if policy else CloudProvider.AWS

            recs.append(
                PolicyRecommendation(
                    id=str(uuid.uuid4())[:8],
                    principal_name=principal,
                    provider=provider,
                    recommendation_type="remove",
                    current_policy=current,
                    suggested_policy=(
                        f"Remove {len(actions)} unused actions: {', '.join(actions[:5])}"
                    ),
                    risk_reduction=15.0,
                    effort="low",
                    description=(f"Remove {len(actions)} unused permissions from {principal}"),
                    auto_applicable=True,
                )
            )

        logger.info(
            "iam_policy_analyzer.recommendations.done",
            rec_count=len(recs),
        )
        return recs

    # ---------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------
    @staticmethod
    def _score_to_risk(score: float) -> RiskLevel:
        """Map numeric risk score to risk level."""
        if score >= 90.0:
            return RiskLevel.CRITICAL
        if score >= 70.0:
            return RiskLevel.HIGH
        if score >= 45.0:
            return RiskLevel.MEDIUM
        if score >= 20.0:
            return RiskLevel.LOW
        return RiskLevel.INFORMATIONAL

    @staticmethod
    def _cis_ref(
        provider: CloudProvider,
        op_type: str,
    ) -> str:
        """Map provider and over-privilege type to CIS ref."""
        refs: dict[str, dict[str, str]] = {
            "aws": {
                "admin": "CIS-AWS-1.16",
                "wildcard": "CIS-AWS-1.22",
                "cross-service": "CIS-AWS-1.16",
            },
            "gcp": {
                "admin": "CIS-GCP-1.4",
                "wildcard": "CIS-GCP-1.5",
                "cross-service": "CIS-GCP-1.6",
            },
            "azure": {
                "admin": "CIS-AZ-1.3",
                "wildcard": "CIS-AZ-1.5",
                "cross-service": "CIS-AZ-1.3",
            },
        }
        provider_refs = refs.get(provider.value, {})
        return provider_refs.get(op_type, "CIS-IAM-1.0")
