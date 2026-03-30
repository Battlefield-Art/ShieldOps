"""Cloud Permission Auditor Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    CloudPermission,
    CrossAccountAccess,
    PermissionFix,
    PermissionScope,
    PermissionViolation,
    ScopeAnalysis,
    ViolationType,
)

logger = structlog.get_logger()

_PERMISSION_PROFILES: list[dict[str, Any]] = [
    {
        "principal": "role/admin-full",
        "principal_type": "role",
        "provider": "AWS",
        "account_id": "111122223333",
        "policy_name": "AdministratorAccess",
        "actions": ["*"],
        "resources": ["*"],
        "scope": PermissionScope.ORGANIZATION,
        "last_used_days": 2,
        "is_wildcard": True,
    },
    {
        "principal": "user/dev-jane",
        "principal_type": "user",
        "provider": "AWS",
        "account_id": "111122223333",
        "policy_name": "PowerUserAccess",
        "actions": [
            "ec2:*",
            "s3:*",
            "lambda:*",
            "rds:*",
        ],
        "resources": ["*"],
        "scope": PermissionScope.ACCOUNT,
        "last_used_days": 5,
        "is_wildcard": True,
    },
    {
        "principal": "sa/ci-deployer",
        "principal_type": "service_account",
        "provider": "AWS",
        "account_id": "111122223333",
        "policy_name": "DeployPolicy",
        "actions": [
            "ecs:UpdateService",
            "ecr:PushImage",
            "s3:PutObject",
        ],
        "resources": [
            "arn:aws:ecs:us-east-1:111122223333:*",
        ],
        "scope": PermissionScope.SERVICE,
        "last_used_days": 1,
        "is_wildcard": False,
    },
    {
        "principal": "sa/legacy-etl",
        "principal_type": "service_account",
        "provider": "AWS",
        "account_id": "111122223333",
        "policy_name": "LegacyETLPolicy",
        "actions": [
            "s3:*",
            "glue:*",
            "redshift:*",
        ],
        "resources": ["*"],
        "scope": PermissionScope.ACCOUNT,
        "last_used_days": 180,
        "is_wildcard": True,
    },
    {
        "principal": "sa/gcp-data-proc",
        "principal_type": "service_account",
        "provider": "GCP",
        "account_id": "proj-analytics-prod",
        "policy_name": "roles/editor",
        "actions": [
            "bigquery.*",
            "storage.*",
            "compute.*",
        ],
        "resources": ["projects/proj-analytics-prod"],
        "scope": PermissionScope.PROJECT,
        "last_used_days": 45,
        "is_wildcard": True,
    },
    {
        "principal": "sp/azure-app-01",
        "principal_type": "service_principal",
        "provider": "Azure",
        "account_id": "sub-prod-001",
        "policy_name": "Contributor",
        "actions": ["*"],
        "resources": [
            "/subscriptions/sub-prod-001",
        ],
        "scope": PermissionScope.ACCOUNT,
        "last_used_days": 120,
        "is_wildcard": True,
    },
    {
        "principal": "user/contractor-bob",
        "principal_type": "user",
        "provider": "AWS",
        "account_id": "444455556666",
        "policy_name": "ReadOnlyAccess",
        "actions": ["s3:GetObject", "s3:ListBucket"],
        "resources": [
            "arn:aws:s3:::prod-data-*",
        ],
        "scope": PermissionScope.RESOURCE,
        "last_used_days": 95,
        "is_wildcard": False,
    },
    {
        "principal": "role/cross-audit",
        "principal_type": "role",
        "provider": "AWS",
        "account_id": "777788889999",
        "policy_name": "CrossAccountAudit",
        "actions": [
            "sts:AssumeRole",
            "iam:ListUsers",
            "iam:ListRoles",
        ],
        "resources": [
            "arn:aws:iam::111122223333:role/*",
        ],
        "scope": PermissionScope.ACCOUNT,
        "last_used_days": 10,
        "is_wildcard": False,
    },
]

_CROSS_ACCOUNT_PROFILES: list[dict[str, Any]] = [
    {
        "source_account": "777788889999",
        "target_account": "111122223333",
        "principal": "role/cross-audit",
        "provider": "AWS",
        "trust_type": "sts:AssumeRole",
        "actions": [
            "iam:ListUsers",
            "iam:ListRoles",
        ],
        "is_external": False,
        "last_used_days": 10,
    },
    {
        "source_account": "999900001111",
        "target_account": "111122223333",
        "principal": "role/vendor-support",
        "provider": "AWS",
        "trust_type": "sts:AssumeRole",
        "actions": ["*"],
        "is_external": True,
        "last_used_days": 200,
    },
    {
        "source_account": "proj-external-vendor",
        "target_account": "proj-analytics-prod",
        "principal": "sa/vendor-ingest",
        "provider": "GCP",
        "trust_type": "serviceAccountUser",
        "actions": [
            "bigquery.datasets.get",
            "bigquery.tables.getData",
        ],
        "is_external": True,
        "last_used_days": 60,
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class CloudPermissionAuditorToolkit:
    """Tools for cloud permission auditing."""

    def __init__(
        self,
        iam_api: Any | None = None,
        cloud_provider: Any | None = None,
    ) -> None:
        self._iam_api = iam_api
        self._cloud_provider = cloud_provider

    async def collect_permissions(
        self,
        tenant_id: str,
    ) -> list[CloudPermission]:
        """Collect IAM permissions across cloud providers."""
        logger.info(
            "cpa.collect_permissions",
            tenant_id=tenant_id,
        )

        if self._iam_api is not None:
            try:
                raw = await self._iam_api.get_permissions(
                    tenant_id=tenant_id,
                )
                return [CloudPermission(**r) for r in raw]
            except Exception:
                logger.exception(
                    "cpa.collect_permissions.error",
                )

        perms: list[CloudPermission] = []
        for i, p in enumerate(_PERMISSION_PROFILES):
            noise = random.randint(0, 5)  # noqa: S311
            perms.append(
                CloudPermission(
                    id=_gen_id("PERM", tenant_id, i),
                    principal=p["principal"],
                    principal_type=p["principal_type"],
                    provider=p["provider"],
                    account_id=p["account_id"],
                    policy_name=p["policy_name"],
                    actions=p["actions"],
                    resources=p["resources"],
                    scope=p["scope"],
                    last_used_days=p["last_used_days"] + noise,
                    is_wildcard=p["is_wildcard"],
                    tags={"env": "production"},
                )
            )
        return perms

    async def analyze_scope(
        self,
        permissions: list[CloudPermission],
    ) -> list[ScopeAnalysis]:
        """Analyze permission scope for each principal."""
        logger.info(
            "cpa.analyze_scope",
            count=len(permissions),
        )

        by_principal: dict[str, list[CloudPermission]] = {}
        for p in permissions:
            by_principal.setdefault(
                p.principal,
                [],
            ).append(p)

        results: list[ScopeAnalysis] = []
        for principal, perms in by_principal.items():
            total_actions = sum(len(p.actions) for p in perms)
            wildcards = sum(1 for p in perms if p.is_wildcard)
            unused_pct = 0.0
            if total_actions > 0:
                dormant = sum(len(p.actions) for p in perms if p.last_used_days > 90)
                unused_pct = round(
                    dormant / total_actions * 100,
                    1,
                )
            risk = min(
                10.0,
                round(
                    wildcards * 3.0 + unused_pct * 0.05 + total_actions * 0.2,
                    1,
                ),
            )
            results.append(
                ScopeAnalysis(
                    principal=principal,
                    provider=perms[0].provider,
                    total_permissions=total_actions,
                    used_permissions=max(
                        0,
                        total_actions - int(total_actions * unused_pct / 100),
                    ),
                    unused_pct=unused_pct,
                    scope=perms[0].scope,
                    risk_score=risk,
                    wildcard_count=wildcards,
                )
            )
        return results

    async def detect_violations(
        self,
        permissions: list[CloudPermission],
        scope_analyses: list[ScopeAnalysis],
    ) -> list[PermissionViolation]:
        """Detect permission violations."""
        logger.info(
            "cpa.detect_violations",
            perms=len(permissions),
        )

        violations: list[PermissionViolation] = []
        idx = 0
        for perm in permissions:
            if perm.is_wildcard and "*" in perm.actions:
                violations.append(
                    PermissionViolation(
                        id=_gen_id("VIO", perm.id, idx),
                        principal=perm.principal,
                        provider=perm.provider,
                        violation_type=(ViolationType.WILDCARD_ACCESS),
                        severity="critical",
                        description=(
                            f"{perm.principal} has wildcard (*) access via {perm.policy_name}"
                        ),
                        affected_actions=perm.actions,
                        affected_resources=(perm.resources),
                        risk_score=9.5,
                    )
                )
                idx += 1
            elif perm.is_wildcard:
                violations.append(
                    PermissionViolation(
                        id=_gen_id("VIO", perm.id, idx),
                        principal=perm.principal,
                        provider=perm.provider,
                        violation_type=(ViolationType.OVERPRIVILEGED),
                        severity="high",
                        description=(
                            f"{perm.principal} has broad wildcard actions in {perm.policy_name}"
                        ),
                        affected_actions=perm.actions,
                        affected_resources=(perm.resources),
                        risk_score=7.5,
                    )
                )
                idx += 1

            if perm.last_used_days > 90:
                vtype = (
                    ViolationType.DORMANT_CREDENTIAL
                    if perm.principal_type in ("service_account", "service_principal")
                    else ViolationType.UNUSED_PERMISSION
                )
                violations.append(
                    PermissionViolation(
                        id=_gen_id("VIO", perm.id, idx),
                        principal=perm.principal,
                        provider=perm.provider,
                        violation_type=vtype,
                        severity="medium",
                        description=(f"{perm.principal} unused for {perm.last_used_days} days"),
                        affected_actions=perm.actions,
                        affected_resources=(perm.resources),
                        risk_score=5.0,
                    )
                )
                idx += 1

        for sa in scope_analyses:
            if sa.risk_score >= 8.0:
                violations.append(
                    PermissionViolation(
                        id=_gen_id("VIO", sa.principal, idx),
                        principal=sa.principal,
                        provider=sa.provider,
                        violation_type=(ViolationType.ESCALATION_PATH),
                        severity="high",
                        description=(
                            f"{sa.principal} has "
                            f"risk score {sa.risk_score}"
                            f" with {sa.wildcard_count}"
                            f" wildcard policies"
                        ),
                        risk_score=sa.risk_score,
                    )
                )
                idx += 1
        return violations

    async def map_cross_account(
        self,
        tenant_id: str,
    ) -> list[CrossAccountAccess]:
        """Map cross-account access relationships."""
        logger.info(
            "cpa.map_cross_account",
            tenant_id=tenant_id,
        )

        entries: list[CrossAccountAccess] = []
        for i, p in enumerate(_CROSS_ACCOUNT_PROFILES):
            risk = 4.0
            if p["is_external"]:
                risk = 7.5
            if "*" in p.get("actions", []):
                risk = 9.0
            if p["last_used_days"] > 90:
                risk = min(10.0, risk + 2.0)

            entries.append(
                CrossAccountAccess(
                    id=_gen_id("XA", tenant_id, i),
                    source_account=p["source_account"],
                    target_account=p["target_account"],
                    principal=p["principal"],
                    provider=p["provider"],
                    trust_type=p["trust_type"],
                    actions=p["actions"],
                    is_external=p["is_external"],
                    last_used_days=p["last_used_days"],
                    risk_score=risk,
                )
            )
        return entries

    async def generate_fixes(
        self,
        violations: list[PermissionViolation],
    ) -> list[PermissionFix]:
        """Generate remediation fixes for violations."""
        logger.info(
            "cpa.generate_fixes",
            count=len(violations),
        )

        fixes: list[PermissionFix] = []
        for i, v in enumerate(violations):
            if v.violation_type == ViolationType.WILDCARD_ACCESS:
                fixes.append(
                    PermissionFix(
                        id=_gen_id("FIX", v.id, i),
                        violation_id=v.id,
                        principal=v.principal,
                        action="restrict_wildcard",
                        description=(
                            f"Replace wildcard (*) with explicit actions for {v.principal}"
                        ),
                        policy_before=('{"Action": ["*"]}'),
                        policy_after=('{"Action": ["ec2:Describe*", "s3:Get*"]}'),
                        auto_applicable=False,
                        risk="medium",
                    )
                )
            elif v.violation_type in (
                ViolationType.DORMANT_CREDENTIAL,
                ViolationType.UNUSED_PERMISSION,
            ):
                fixes.append(
                    PermissionFix(
                        id=_gen_id("FIX", v.id, i),
                        violation_id=v.id,
                        principal=v.principal,
                        action="revoke_unused",
                        description=(f"Revoke unused permissions for {v.principal}"),
                        policy_before=('{"Effect": "Allow"}'),
                        policy_after=('{"Effect": "Deny"}'),
                        auto_applicable=(v.severity != "critical"),
                        risk="low",
                    )
                )
            elif v.violation_type == ViolationType.OVERPRIVILEGED:
                fixes.append(
                    PermissionFix(
                        id=_gen_id("FIX", v.id, i),
                        violation_id=v.id,
                        principal=v.principal,
                        action="scope_reduction",
                        description=(f"Reduce scope of {v.principal} to least privilege"),
                        policy_before=('{"Resource": ["*"]}'),
                        policy_after=('{"Resource": ["arn:aws:s3:::bucket"]}'),
                        auto_applicable=False,
                        risk="medium",
                    )
                )
            else:
                fixes.append(
                    PermissionFix(
                        id=_gen_id("FIX", v.id, i),
                        violation_id=v.id,
                        principal=v.principal,
                        action="review_required",
                        description=(f"Manual review needed for {v.principal}: {v.description}"),
                        auto_applicable=False,
                        risk="high",
                    )
                )
        return fixes
