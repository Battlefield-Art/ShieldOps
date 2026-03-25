"""Service Account Tracker — Tool functions for cloud service account governance."""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any

import structlog

from .models import (
    AccountStatus,
    CloudSource,
    RemediationAction,
    ServiceAccount,
    SharingDetection,
    UsageAnomaly,
)

logger = structlog.get_logger()

# Thresholds
_DORMANT_DAYS = 90
_ORPHANED_DAYS = 180
_HIGH_PERMISSION_KEYWORDS = [
    "admin",
    "root",
    "delete",
    "iam:*",
    "s3:*",
    "ec2:*",
    "Owner",
    "Contributor",
    "roles/editor",
    "cluster-admin",
]
_MAX_KEY_AGE_DAYS = 90
_MAX_KEYS_PER_ACCOUNT = 2


class ServiceAccountTrackerToolkit:
    """Tools for discovering, analysing, and remediating service accounts."""

    def __init__(
        self,
        cloud_connectors: dict[str, Any] | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._connectors = cloud_connectors or {}
        self._policy_engine = policy_engine
        self._repository = repository
        self._accounts: dict[str, ServiceAccount] = {}

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def discover_accounts(
        self,
        tenant_id: str,
        sources: list[str] | None = None,
    ) -> list[ServiceAccount]:
        """Discover service accounts across configured cloud providers."""
        logger.info(
            "sa_tracker.discover",
            tenant_id=tenant_id,
            sources=sources,
        )
        sources = sources or [s.value for s in CloudSource]
        discovered: list[ServiceAccount] = []

        for source in sources:
            connector = self._connectors.get(source)
            if connector and hasattr(connector, "list_service_accounts"):
                try:
                    raw = await connector.list_service_accounts(tenant_id=tenant_id)
                    for entry in raw:
                        sa = self._normalise_account(entry, source)
                        discovered.append(sa)
                except Exception:
                    logger.exception("sa_tracker.discover.error", source=source)
            else:
                # Generate placeholder inventory when connector unavailable
                discovered.extend(self._generate_placeholder_accounts(tenant_id, source))

        for sa in discovered:
            self._accounts[sa.id] = sa
        return discovered

    async def fetch_usage_logs(
        self,
        account_id: str,
        window_days: int = 90,
    ) -> list[dict[str, Any]]:
        """Fetch usage/activity logs for a service account."""
        logger.info(
            "sa_tracker.fetch_usage",
            account_id=account_id,
            window_days=window_days,
        )
        sa = self._accounts.get(account_id)
        if not sa:
            return []

        connector = self._connectors.get(sa.cloud_source.value)
        if connector and hasattr(connector, "get_activity_logs"):
            try:
                return await connector.get_activity_logs(
                    account_id=account_id,
                    window_days=window_days,
                )
            except Exception:
                logger.exception("sa_tracker.fetch_usage.error")
                return []

        # Synthetic usage when no connector
        return self._synthetic_usage(account_id, window_days)

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    async def detect_credential_sharing(
        self,
        account_id: str,
        usage_logs: list[dict[str, Any]],
    ) -> SharingDetection | None:
        """Detect if a service account credential is used from multiple sources."""
        logger.info("sa_tracker.detect_sharing", account_id=account_id)
        source_ips = {log.get("source_ip", "") for log in usage_logs if log.get("source_ip")}
        user_agents = {log.get("user_agent", "") for log in usage_logs if log.get("user_agent")}

        # Heuristic: multiple distinct IPs + user-agents suggests sharing
        if len(source_ips) > 3 or len(user_agents) > 2:
            return SharingDetection(
                id=f"share-{uuid.uuid4().hex[:8]}",
                account_id=account_id,
                shared_with=sorted(source_ips)[:10],
                detection_method="ip_and_ua_diversity",
                risk_level="high" if len(source_ips) > 5 else "medium",
            )
        return None

    async def detect_usage_anomalies(
        self,
        account_id: str,
        usage_logs: list[dict[str, Any]],
    ) -> list[UsageAnomaly]:
        """Identify anomalous usage patterns for a service account."""
        logger.info("sa_tracker.detect_anomalies", account_id=account_id)
        anomalies: list[UsageAnomaly] = []
        sa = self._accounts.get(account_id)

        if not usage_logs:
            return anomalies

        # Off-hours access
        off_hours = [
            log for log in usage_logs if log.get("hour", 12) < 6 or log.get("hour", 12) > 22
        ]
        if len(off_hours) > len(usage_logs) * 0.3:
            anomalies.append(
                UsageAnomaly(
                    id=f"anom-{uuid.uuid4().hex[:8]}",
                    account_id=account_id,
                    anomaly_type="off_hours_access",
                    description=(
                        f"{len(off_hours)}/{len(usage_logs)} calls outside business hours"
                    ),
                    severity="medium",
                    confidence=0.75,
                    timestamp=time.time(),
                )
            )

        # Geo-impossible travel
        locations = [log.get("geo", "") for log in usage_logs if log.get("geo")]
        unique_geos = set(locations)
        if len(unique_geos) > 3:
            anomalies.append(
                UsageAnomaly(
                    id=f"anom-{uuid.uuid4().hex[:8]}",
                    account_id=account_id,
                    anomaly_type="impossible_travel",
                    description=(f"Activity from {len(unique_geos)} distinct locations"),
                    severity="high",
                    confidence=0.85,
                    timestamp=time.time(),
                )
            )

        # Privilege escalation attempt
        priv_calls = [
            log
            for log in usage_logs
            if any(
                kw in log.get("action", "").lower()
                for kw in ("attach", "policy", "role", "grant", "escalat")
            )
        ]
        if priv_calls:
            anomalies.append(
                UsageAnomaly(
                    id=f"anom-{uuid.uuid4().hex[:8]}",
                    account_id=account_id,
                    anomaly_type="privilege_escalation_attempt",
                    description=(f"{len(priv_calls)} privilege-modifying API calls detected"),
                    severity="critical",
                    confidence=0.7,
                    source_ip=priv_calls[0].get("source_ip", ""),
                    timestamp=time.time(),
                )
            )

        # Excessive key count
        if sa and sa.key_count > _MAX_KEYS_PER_ACCOUNT:
            anomalies.append(
                UsageAnomaly(
                    id=f"anom-{uuid.uuid4().hex[:8]}",
                    account_id=account_id,
                    anomaly_type="excessive_keys",
                    description=(f"Account has {sa.key_count} keys (max {_MAX_KEYS_PER_ACCOUNT})"),
                    severity="medium",
                    confidence=0.95,
                    timestamp=time.time(),
                )
            )

        return anomalies

    # ------------------------------------------------------------------
    # Risk classification
    # ------------------------------------------------------------------

    async def classify_risk(
        self,
        account: ServiceAccount,
        anomalies: list[UsageAnomaly],
        sharing: SharingDetection | None = None,
    ) -> ServiceAccount:
        """Compute risk score and status for a service account."""
        logger.info("sa_tracker.classify_risk", account_id=account.id)
        risk = 0.0

        # Dormancy / orphaned
        if account.days_inactive >= _ORPHANED_DAYS:
            account.status = AccountStatus.ORPHANED
            risk += 0.4
        elif account.days_inactive >= _DORMANT_DAYS:
            account.status = AccountStatus.DORMANT
            risk += 0.2

        # Sharing
        if sharing:
            account.status = AccountStatus.SHARED
            risk += 0.3

        # Over-privileged
        perm_str = " ".join(account.permissions).lower()
        if any(kw.lower() in perm_str for kw in _HIGH_PERMISSION_KEYWORDS):
            risk += 0.2

        # No MFA
        if not account.mfa_enabled:
            risk += 0.1

        # Anomaly severity
        severity_weights = {
            "critical": 0.3,
            "high": 0.2,
            "medium": 0.1,
            "low": 0.05,
        }
        for a in anomalies:
            risk += severity_weights.get(a.severity, 0.05)

        # Critical anomaly → compromised
        if any(a.severity == "critical" for a in anomalies):
            account.status = AccountStatus.COMPROMISED

        account.risk_score = round(min(risk, 1.0), 4)
        self._accounts[account.id] = account
        return account

    # ------------------------------------------------------------------
    # Remediation
    # ------------------------------------------------------------------

    async def propose_remediations(
        self,
        account: ServiceAccount,
        anomalies: list[UsageAnomaly],
        sharing: SharingDetection | None = None,
    ) -> list[RemediationAction]:
        """Propose remediation actions based on risk classification."""
        logger.info("sa_tracker.propose_remediations", account_id=account.id)
        actions: list[RemediationAction] = []

        if account.status == AccountStatus.ORPHANED:
            actions.append(
                RemediationAction(
                    id=f"rem-{uuid.uuid4().hex[:8]}",
                    account_id=account.id,
                    action="disable_account",
                    description=(f"Disable orphaned account (inactive {account.days_inactive}d)"),
                )
            )

        if account.status == AccountStatus.DORMANT:
            actions.append(
                RemediationAction(
                    id=f"rem-{uuid.uuid4().hex[:8]}",
                    account_id=account.id,
                    action="rotate_credentials",
                    description="Rotate credentials for dormant account",
                )
            )

        if sharing:
            actions.append(
                RemediationAction(
                    id=f"rem-{uuid.uuid4().hex[:8]}",
                    account_id=account.id,
                    action="revoke_shared_credentials",
                    description=(
                        f"Revoke credentials shared with {len(sharing.shared_with)} sources"
                    ),
                )
            )

        if not account.mfa_enabled:
            actions.append(
                RemediationAction(
                    id=f"rem-{uuid.uuid4().hex[:8]}",
                    account_id=account.id,
                    action="enforce_mfa",
                    description="Enforce MFA on service account",
                )
            )

        if account.key_count > _MAX_KEYS_PER_ACCOUNT:
            actions.append(
                RemediationAction(
                    id=f"rem-{uuid.uuid4().hex[:8]}",
                    account_id=account.id,
                    action="deactivate_excess_keys",
                    description=(
                        f"Deactivate excess keys ({account.key_count} > {_MAX_KEYS_PER_ACCOUNT})"
                    ),
                )
            )

        if account.status == AccountStatus.COMPROMISED:
            actions.append(
                RemediationAction(
                    id=f"rem-{uuid.uuid4().hex[:8]}",
                    account_id=account.id,
                    action="quarantine_account",
                    description=(
                        "Quarantine compromised account — revoke all "
                        "sessions and rotate keys immediately"
                    ),
                )
            )

        perm_str = " ".join(account.permissions).lower()
        if any(kw.lower() in perm_str for kw in _HIGH_PERMISSION_KEYWORDS):
            actions.append(
                RemediationAction(
                    id=f"rem-{uuid.uuid4().hex[:8]}",
                    account_id=account.id,
                    action="scope_down_permissions",
                    description="Reduce over-privileged permissions to least-privilege",
                )
            )

        return actions

    async def apply_remediation(
        self,
        action: RemediationAction,
    ) -> RemediationAction:
        """Apply a single remediation action (delegates to connector)."""
        logger.info(
            "sa_tracker.apply_remediation",
            account_id=action.account_id,
            action=action.action,
        )
        sa = self._accounts.get(action.account_id)
        connector = None
        if sa:
            connector = self._connectors.get(sa.cloud_source.value)

        if connector and hasattr(connector, "apply_remediation"):
            try:
                result = await connector.apply_remediation(
                    account_id=action.account_id,
                    action=action.action,
                )
                action.applied = True
                action.success = result.get("success", False)
            except Exception:
                logger.exception("sa_tracker.apply_remediation.error")
                action.applied = True
                action.success = False
        else:
            # Mark as proposed-only when no connector available
            action.applied = False
            action.success = False

        return action

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalise_account(self, raw: dict[str, Any], source: str) -> ServiceAccount:
        """Normalise a raw account dict into a ServiceAccount model."""
        now = time.time()
        last_used = raw.get("last_used", 0.0) or 0.0
        days_inactive = int((now - last_used) / 86400) if last_used else 999

        return ServiceAccount(
            id=raw.get("id", f"sa-{uuid.uuid4().hex[:8]}"),
            name=raw.get("name", raw.get("email", "")),
            cloud_source=(
                CloudSource(source)
                if source in CloudSource._value2member_map_
                else CloudSource.AWS_IAM
            ),
            owner=raw.get("owner", ""),
            created_at=raw.get("created_at", now),
            last_used=last_used,
            days_inactive=days_inactive,
            permissions=raw.get("permissions", []),
            mfa_enabled=raw.get("mfa_enabled", False),
            key_count=raw.get("key_count", 1),
            status=AccountStatus.ACTIVE,
            risk_score=0.0,
        )

    def _generate_placeholder_accounts(
        self,
        tenant_id: str,
        source: str,
    ) -> list[ServiceAccount]:
        """Generate placeholder accounts for demo / offline mode."""
        now = time.time()
        prefix = hashlib.sha256(f"{tenant_id}:{source}".encode()).hexdigest()[:6]
        cloud = (
            CloudSource(source) if source in CloudSource._value2member_map_ else CloudSource.AWS_IAM
        )
        return [
            ServiceAccount(
                id=f"sa-{prefix}-{i}",
                name=f"svc-{source.split('_')[0]}-{i}@{tenant_id}",
                cloud_source=cloud,
                owner=f"team-{i % 3}@{tenant_id}",
                created_at=now - (i * 86400 * 30),
                last_used=now - (i * 86400 * 45),
                days_inactive=i * 45,
                permissions=[
                    "read" if i % 2 == 0 else "admin",
                ],
                mfa_enabled=i % 3 == 0,
                key_count=i % 4,
            )
            for i in range(1, 4)
        ]

    def _synthetic_usage(
        self,
        account_id: str,
        window_days: int,
    ) -> list[dict[str, Any]]:
        """Return synthetic usage logs for offline analysis."""
        now = time.time()
        return [
            {
                "account_id": account_id,
                "timestamp": now - (d * 86400),
                "action": "sts:AssumeRole" if d % 3 == 0 else "s3:GetObject",
                "source_ip": f"10.0.{d % 5}.{d % 256}",
                "user_agent": f"sdk-python/{d % 3}",
                "hour": (8 + d) % 24,
                "geo": ["us-east-1", "eu-west-1", "ap-south-1"][d % 3],
            }
            for d in range(min(window_days, 30))
        ]
