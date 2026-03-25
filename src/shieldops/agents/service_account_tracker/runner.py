"""Service Account Tracker — Entry point and lifecycle management."""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from .graph import build_graph
from .tools import ServiceAccountTrackerToolkit

logger = structlog.get_logger()


class ServiceAccountTrackerRunner:
    """Runs the Service Account Tracker workflow."""

    def __init__(
        self,
        cloud_connectors: dict[str, Any] | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ServiceAccountTrackerToolkit(
            cloud_connectors=cloud_connectors,
            policy_engine=policy_engine,
            repository=repository,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("sa_tracker_runner.init")

    async def track(
        self,
        tenant_id: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full service account tracking workflow.

        Args:
            tenant_id: The tenant to scan for service accounts.
            context: Optional overrides (sources, thresholds, etc.).

        Returns:
            Final state dict with accounts, anomalies, remediations, stats.
        """
        context = context or {}
        request_id = context.get("request_id", f"sat-{uuid.uuid4().hex[:12]}")

        initial_state: dict[str, Any] = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "reasoning_chain": [],
        }

        logger.info(
            "sa_tracker_runner.track",
            tenant_id=tenant_id,
            request_id=request_id,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("sa_tracker_runner.track.error")
            raise

    async def discover_only(
        self,
        tenant_id: str,
    ) -> list[dict[str, Any]]:
        """Run discovery only — return raw service account inventory.

        Useful for quick inventory scans without full analysis.
        """
        logger.info("sa_tracker_runner.discover_only", tenant_id=tenant_id)
        accounts = await self._toolkit.discover_accounts(tenant_id=tenant_id)
        return [a.model_dump() for a in accounts]

    async def check_account(
        self,
        tenant_id: str,
        account_id: str,
    ) -> dict[str, Any]:
        """Run a focused check on a single service account.

        Discovers the account, fetches usage, detects anomalies,
        and classifies risk — without the full graph invocation.
        """
        logger.info(
            "sa_tracker_runner.check_account",
            tenant_id=tenant_id,
            account_id=account_id,
        )
        # Ensure account is in the toolkit cache
        accounts = await self._toolkit.discover_accounts(tenant_id=tenant_id)
        target = None
        for acct in accounts:
            if acct.id == account_id:
                target = acct
                break

        if not target:
            return {"error": f"Account {account_id} not found", "account_id": account_id}

        usage_logs = await self._toolkit.fetch_usage_logs(
            account_id=account_id,
            window_days=90,
        )
        anomalies = await self._toolkit.detect_usage_anomalies(
            account_id=account_id,
            usage_logs=usage_logs,
        )
        sharing = await self._toolkit.detect_credential_sharing(
            account_id=account_id,
            usage_logs=usage_logs,
        )
        target = await self._toolkit.classify_risk(
            account=target,
            anomalies=anomalies,
            sharing=sharing,
        )

        return {
            "account": target.model_dump(),
            "anomalies": [a.model_dump() for a in anomalies],
            "sharing": sharing.model_dump() if sharing else None,
            "usage_log_count": len(usage_logs),
        }

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist tracking results to the repository."""
        if self._repository:
            await self._repository.save_tracker_run(result)
