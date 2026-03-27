"""Tool functions for the Access Remediation Agent."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.agents.access_remediation.models import (
    AccessAudit,
    AccessChange,
    AccessIssue,
    AccessVerification,
    ActionType,
    ExcessAccess,
    RemediationPlan,
)

logger = structlog.get_logger()


class AccessRemediationToolkit:
    """Tools for access audit and remediation."""

    def __init__(
        self,
        opa_client: Any = None,
        idp_client: Any = None,
    ) -> None:
        self._opa = opa_client
        self._idp = idp_client

    async def audit_access(
        self,
        provider: str,
    ) -> list[AccessAudit]:
        """Audit all accounts for a provider."""
        # Simulated — production queries IdP / IAM APIs
        audits = [
            AccessAudit(
                account_id="user-alice",
                account_type="user",
                provider=provider,
                last_login_days=2,
                permission_count=15,
                mfa_enabled=True,
                has_admin=False,
                owner_email="alice@corp.com",
            ),
            AccessAudit(
                account_id="user-bob",
                account_type="user",
                provider=provider,
                last_login_days=180,
                permission_count=42,
                mfa_enabled=False,
                has_admin=True,
                owner_email="bob@corp.com",
            ),
            AccessAudit(
                account_id="svc-deploy",
                account_type="service_account",
                provider=provider,
                last_login_days=400,
                permission_count=8,
                mfa_enabled=False,
                has_admin=False,
                owner_email="ops@corp.com",
            ),
            AccessAudit(
                account_id="user-carol",
                account_type="user",
                provider=provider,
                last_login_days=5,
                permission_count=120,
                mfa_enabled=True,
                has_admin=True,
                owner_email="carol@corp.com",
            ),
        ]
        logger.info(
            "access_audited",
            count=len(audits),
            provider=provider,
        )
        return audits

    async def identify_excess(
        self,
        audits: list[AccessAudit],
    ) -> list[ExcessAccess]:
        """Identify excess access from audit results."""
        excess: list[ExcessAccess] = []

        for audit in audits:
            if audit.last_login_days > 90:
                issue = (
                    AccessIssue.DORMANT_ACCOUNT
                    if audit.last_login_days > 180
                    else AccessIssue.STALE_ACCESS
                )
                excess.append(
                    ExcessAccess(
                        audit_id=audit.id,
                        account_id=audit.account_id,
                        issue_type=issue,
                        severity="high",
                        description=(f"No login in {audit.last_login_days}d"),
                        grace_period_hours=72,
                    )
                )

            if audit.permission_count > 50:
                excess.append(
                    ExcessAccess(
                        audit_id=audit.id,
                        account_id=audit.account_id,
                        issue_type=(AccessIssue.OVER_PRIVILEGED),
                        severity="medium",
                        description=(f"{audit.permission_count} permissions"),
                        permissions_affected=["excess_permissions"],
                        grace_period_hours=72,
                    )
                )

            if audit.has_admin and not audit.mfa_enabled:
                excess.append(
                    ExcessAccess(
                        audit_id=audit.id,
                        account_id=audit.account_id,
                        issue_type=(AccessIssue.EXCESSIVE_SCOPE),
                        severity="critical",
                        description=("Admin without MFA"),
                        grace_period_hours=0,
                    )
                )

        logger.info(
            "excess_access_identified",
            count=len(excess),
        )
        return excess

    async def plan_change(
        self,
        excess: ExcessAccess,
    ) -> RemediationPlan:
        """Create a remediation plan for an excess."""
        action_map = {
            AccessIssue.STALE_ACCESS: ActionType.REVOKE,
            AccessIssue.DORMANT_ACCOUNT: (ActionType.DISABLE),
            AccessIssue.OVER_PRIVILEGED: (ActionType.RESTRICT),
            AccessIssue.SHARED_CREDENTIAL: (ActionType.ROTATE),
            AccessIssue.ORPHANED_PERMISSION: (ActionType.REVOKE),
            AccessIssue.EXCESSIVE_SCOPE: (ActionType.RESTRICT),
        }
        action = action_map.get(excess.issue_type, ActionType.NOTIFY_OWNER)
        is_admin = excess.severity == "critical"

        return RemediationPlan(
            excess_id=excess.id,
            account_id=excess.account_id,
            action=action,
            description=(f"{action.value} for {excess.issue_type}: {excess.description}"),
            approval_required=is_admin,
            grace_expires_at=(time.time() + excess.grace_period_hours * 3600),
        )

    async def execute_change(
        self,
        plan: RemediationPlan,
    ) -> AccessChange:
        """Execute an access change."""
        # Simulated — production calls IdP API
        change = AccessChange(
            plan_id=plan.id,
            account_id=plan.account_id,
            action=plan.action,
            success=True,
            executed_at=time.time(),
            rollback_info=(f"Re-enable {plan.account_id}"),
        )
        logger.info(
            "access_change_executed",
            account=plan.account_id,
            action=plan.action,
        )
        return change

    async def verify_change(
        self,
        change: AccessChange,
    ) -> AccessVerification:
        """Verify an access change was applied."""
        # Simulated — production re-checks access
        return AccessVerification(
            change_id=change.id,
            account_id=change.account_id,
            verified=True,
            access_still_exists=False,
            details=(f"Access {change.action} confirmed."),
        )

    async def notify_owner(
        self,
        plan: RemediationPlan,
    ) -> bool:
        """Notify account owner of pending change."""
        logger.info(
            "owner_notified",
            account=plan.account_id,
            action=plan.action,
        )
        return True
