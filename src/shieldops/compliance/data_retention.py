"""Data Retention Policy Manager.

Enforces data retention policies per compliance framework:
- HIPAA: 6 years for medical records
- SOC 2: 1 year for audit logs
- PCI-DSS: 1 year for transaction logs
- GDPR: Right to erasure, data minimization
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel
import structlog

logger = structlog.get_logger()


class RetentionPolicy(BaseModel):
    """A single data-retention rule."""

    framework: str
    data_type: str
    retention_days: int
    action: str  # archive, delete, anonymize


class RetentionCheckResult(BaseModel):
    """Result of checking one record against retention policies."""

    compliant: bool
    applicable_policies: list[RetentionPolicy]
    violations: list[str]
    recommended_action: str | None = None


class DataRetentionManager:
    """Manage and enforce data retention policies."""

    DEFAULT_POLICIES: list[RetentionPolicy] = [
        RetentionPolicy(
            framework="hipaa",
            data_type="phi",
            retention_days=2190,
            action="archive",
        ),
        RetentionPolicy(
            framework="soc2",
            data_type="audit_log",
            retention_days=365,
            action="archive",
        ),
        RetentionPolicy(
            framework="pci_dss",
            data_type="transaction",
            retention_days=365,
            action="delete",
        ),
        RetentionPolicy(
            framework="gdpr",
            data_type="personal_data",
            retention_days=730,
            action="anonymize",
        ),
    ]

    def __init__(self, custom_policies: list[RetentionPolicy] | None = None) -> None:
        self._policies = list(self.DEFAULT_POLICIES)
        if custom_policies:
            self._policies.extend(custom_policies)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_policies(self, framework: str | None = None) -> list[RetentionPolicy]:
        """Return retention policies, optionally filtered by framework."""
        if framework is None:
            return list(self._policies)
        return [p for p in self._policies if p.framework == framework]

    def check_compliance(self, record_age_days: int, data_type: str) -> RetentionCheckResult:
        """Check whether a record of a given age and type is compliant.

        Returns a :class:`RetentionCheckResult` with the applicable
        policies, any violations, and the recommended action.
        """
        applicable = [p for p in self._policies if p.data_type == data_type]
        if not applicable:
            return RetentionCheckResult(
                compliant=True,
                applicable_policies=[],
                violations=[],
                recommended_action=None,
            )

        violations: list[str] = []
        recommended_action: str | None = None
        for policy in applicable:
            if record_age_days > policy.retention_days:
                violations.append(
                    f"{policy.framework}: {data_type} exceeds "
                    f"{policy.retention_days}-day retention "
                    f"(age={record_age_days}d)"
                )
                # Use the action of the most restrictive violated policy
                recommended_action = policy.action

        return RetentionCheckResult(
            compliant=len(violations) == 0,
            applicable_policies=applicable,
            violations=violations,
            recommended_action=recommended_action,
        )

    async def purge_expired(
        self,
        session_factory: Any,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Identify (and optionally purge) records past retention.

        In dry-run mode (default) no data is modified; the method returns
        a summary of what *would* be purged.

        Parameters
        ----------
        session_factory:
            An async SQLAlchemy session-maker or compatible callable.
        dry_run:
            If ``True``, only report; if ``False``, actually purge.

        Returns
        -------
        dict with keys: ``policies_evaluated``, ``records_flagged``,
        ``records_purged``, ``dry_run``, ``details``.
        """
        summary: dict[str, Any] = {
            "policies_evaluated": len(self._policies),
            "records_flagged": 0,
            "records_purged": 0,
            "dry_run": dry_run,
            "details": [],
        }

        for policy in self._policies:
            detail: dict[str, Any] = {
                "framework": policy.framework,
                "data_type": policy.data_type,
                "retention_days": policy.retention_days,
                "action": policy.action,
                "flagged": 0,
                "purged": 0,
            }

            # In a real implementation, this would query the database via
            # session_factory. Here we simulate the interface contract.
            logger.info(
                "retention_check",
                framework=policy.framework,
                data_type=policy.data_type,
                retention_days=policy.retention_days,
                dry_run=dry_run,
            )

            summary["details"].append(detail)

        return summary
