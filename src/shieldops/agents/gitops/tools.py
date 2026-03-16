"""Tool functions for the GitOps Agent.

These bridge Git repositories, infrastructure connectors, and deployment
systems to the agent's LangGraph nodes. Each tool is a self-contained
async function that queries external systems and returns structured data.
"""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.gitops.models import (
    ApplyResult,
    DriftItem,
    DriftType,
    ReconciliationAction,
    ReconciliationPlan,
)
from shieldops.connectors.base import ConnectorRouter

logger = structlog.get_logger()


class GitOpsToolkit:
    """Collection of tools available to the GitOps agent.

    Injected into nodes at graph construction time to decouple agent logic
    from specific connector implementations.
    """

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        repository: Any = None,
    ) -> None:
        self._router = connector_router
        self._repository = repository

    async def detect_drift(
        self,
        repo_url: str,
        branch: str = "main",
        namespace: str = "",
    ) -> list[DriftItem]:
        """Compare git desired state vs actual infrastructure state.

        Fetches manifests from the Git repository and compares them against
        the live infrastructure to identify drift.

        Returns:
            List of DriftItem objects describing each detected difference.
        """
        logger.info(
            "gitops_detecting_drift",
            repo_url=repo_url,
            branch=branch,
            namespace=namespace,
        )

        drift_items: list[DriftItem] = []

        if self._router is None:
            logger.warning("gitops_no_connector_router")
            return drift_items

        try:
            connector = self._router.get("kubernetes")

            # Fetch desired state from git
            desired_state = await self._fetch_desired_state(repo_url, branch, namespace)

            # Fetch actual state from infrastructure
            actual_state = await self._fetch_actual_state(connector, namespace)

            # Compare states
            drift_items = self._compare_states(desired_state, actual_state, namespace)

        except (ValueError, Exception) as e:
            logger.error(
                "gitops_drift_detection_failed",
                repo_url=repo_url,
                error=str(e),
            )

        return drift_items

    async def generate_reconciliation_plan(
        self,
        drift_items: list[DriftItem],
    ) -> ReconciliationPlan:
        """Create an action plan from detected drift items.

        Analyzes drift items and determines the appropriate action for each,
        estimates risk, and determines if approval is needed.

        Returns:
            A ReconciliationPlan with ordered actions.
        """
        logger.info(
            "gitops_generating_plan",
            drift_count=len(drift_items),
        )

        if not drift_items:
            return ReconciliationPlan(
                items=[],
                actions=[],
                estimated_risk=0.0,
                requires_approval=False,
            )

        actions: list[ReconciliationAction] = []
        risk_scores: list[float] = []

        for item in drift_items:
            action = self._determine_action(item)
            actions.append(action)
            risk_scores.append(self._assess_item_risk(item, action))

        estimated_risk = max(risk_scores) if risk_scores else 0.0

        # Require approval for high-risk or destructive operations
        requires_approval = (
            estimated_risk > 0.5
            or ReconciliationAction.DELETE in actions
            or any(
                item.drift_type in (DriftType.SECRET_DRIFT, DriftType.POLICY_DRIFT)
                for item in drift_items
            )
        )

        return ReconciliationPlan(
            items=drift_items,
            actions=actions,
            estimated_risk=min(estimated_risk, 1.0),
            requires_approval=requires_approval,
        )

    async def apply_changes(
        self,
        plan: ReconciliationPlan,
        dry_run: bool = True,
    ) -> list[ApplyResult]:
        """Apply reconciliation actions from the plan.

        Args:
            plan: The reconciliation plan to execute.
            dry_run: If True, simulate changes without applying.

        Returns:
            List of ApplyResult for each action taken.
        """
        logger.info(
            "gitops_applying_changes",
            action_count=len(plan.actions),
            dry_run=dry_run,
        )

        results: list[ApplyResult] = []

        for item, action in zip(plan.items, plan.actions, strict=True):
            start = datetime.now(UTC)

            if action == ReconciliationAction.NO_OP:
                results.append(
                    ApplyResult(
                        resource_id=item.resource_id,
                        action=action,
                        success=True,
                        duration_seconds=0.0,
                        rollback_available=False,
                    )
                )
                continue

            if dry_run:
                results.append(
                    ApplyResult(
                        resource_id=item.resource_id,
                        action=action,
                        success=True,
                        duration_seconds=0.0,
                        rollback_available=True,
                        error=None,
                    )
                )
                logger.info(
                    "gitops_dry_run_action",
                    resource_id=item.resource_id,
                    action=action,
                )
                continue

            try:
                await self._execute_action(item, action)
                elapsed = (datetime.now(UTC) - start).total_seconds()
                results.append(
                    ApplyResult(
                        resource_id=item.resource_id,
                        action=action,
                        success=True,
                        duration_seconds=elapsed,
                        rollback_available=action != ReconciliationAction.DELETE,
                    )
                )
            except Exception as e:
                elapsed = (datetime.now(UTC) - start).total_seconds()
                logger.error(
                    "gitops_apply_failed",
                    resource_id=item.resource_id,
                    action=action,
                    error=str(e),
                )
                results.append(
                    ApplyResult(
                        resource_id=item.resource_id,
                        action=action,
                        success=False,
                        duration_seconds=elapsed,
                        rollback_available=False,
                        error=str(e),
                    )
                )

        return results

    async def verify_deployment(
        self,
        results: list[ApplyResult],
    ) -> bool:
        """Verify that reconciliation was successful.

        Checks that all applied changes took effect and resources
        are healthy.

        Returns:
            True if all verifications pass.
        """
        logger.info(
            "gitops_verifying_deployment",
            result_count=len(results),
        )

        if not results:
            return True

        # Check all results succeeded
        all_success = all(r.success for r in results)
        if not all_success:
            failed = [r for r in results if not r.success]
            logger.warning(
                "gitops_verification_failed",
                failed_count=len(failed),
                failed_resources=[r.resource_id for r in failed],
            )
            return False

        # If connector is available, verify resource health
        if self._router is not None:
            try:
                connector = self._router.get("kubernetes")
                for result in results:
                    if result.action == ReconciliationAction.NO_OP:
                        continue
                    health = await connector.get_health(result.resource_id)
                    if not health.healthy:
                        logger.warning(
                            "gitops_resource_unhealthy",
                            resource_id=result.resource_id,
                        )
                        return False
            except (ValueError, Exception) as e:
                logger.error("gitops_health_check_failed", error=str(e))
                return False

        return True

    async def get_change_history(
        self,
        namespace: str,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Retrieve recent change history for a namespace.

        Returns:
            List of recent changes with metadata.
        """
        if self._repository is None:
            return []

        try:
            history: list[dict[str, Any]] = await self._repository.get_change_history(
                namespace=namespace,
                limit=limit,
            )
            return history
        except Exception as e:
            logger.warning("gitops_history_query_failed", error=str(e))
            return []

    # --- Private helpers ---

    async def _fetch_desired_state(
        self,
        repo_url: str,
        branch: str,
        namespace: str,
    ) -> dict[str, Any]:
        """Fetch desired state from a Git repository."""
        # In production, this would clone/fetch the repo and parse manifests.
        # Returns a dict keyed by resource_id with desired specs.
        return {}

    async def _fetch_actual_state(
        self,
        connector: Any,
        namespace: str,
    ) -> dict[str, Any]:
        """Fetch actual state from live infrastructure."""
        # In production, this queries K8s API or cloud provider.
        return {}

    def _compare_states(
        self,
        desired: dict[str, Any],
        actual: dict[str, Any],
        namespace: str,
    ) -> list[DriftItem]:
        """Compare desired vs actual state and return drift items."""
        drift_items: list[DriftItem] = []

        # Resources in desired but not actual → need creation
        for resource_id, spec in desired.items():
            if resource_id not in actual:
                drift_items.append(
                    DriftItem(
                        resource_id=resource_id,
                        resource_type=spec.get("kind", "unknown"),
                        drift_type=DriftType.RESOURCE_DRIFT,
                        expected_value=str(spec),
                        actual_value="<missing>",
                        severity="high",
                        namespace=namespace,
                    )
                )
            elif actual[resource_id] != spec:
                drift_items.append(
                    DriftItem(
                        resource_id=resource_id,
                        resource_type=spec.get("kind", "unknown"),
                        drift_type=DriftType.CONFIG_DRIFT,
                        expected_value=str(spec),
                        actual_value=str(actual[resource_id]),
                        severity="medium",
                        namespace=namespace,
                    )
                )

        # Resources in actual but not desired → potential deletion
        for resource_id in actual:
            if resource_id not in desired:
                drift_items.append(
                    DriftItem(
                        resource_id=resource_id,
                        resource_type=actual[resource_id].get("kind", "unknown"),
                        drift_type=DriftType.RESOURCE_DRIFT,
                        expected_value="<should_not_exist>",
                        actual_value=str(actual[resource_id]),
                        severity="medium",
                        namespace=namespace,
                    )
                )

        return drift_items

    @staticmethod
    def _determine_action(item: DriftItem) -> ReconciliationAction:
        """Determine the appropriate reconciliation action for a drift item."""
        if item.actual_value == "<missing>":
            return ReconciliationAction.CREATE
        if item.expected_value == "<should_not_exist>":
            return ReconciliationAction.DELETE
        if item.drift_type == DriftType.VERSION_DRIFT:
            return ReconciliationAction.ROLLBACK
        return ReconciliationAction.UPDATE

    @staticmethod
    def _assess_item_risk(item: DriftItem, action: ReconciliationAction) -> float:
        """Assess risk for a single drift item and action pair."""
        base_risk = {
            ReconciliationAction.NO_OP: 0.0,
            ReconciliationAction.CREATE: 0.2,
            ReconciliationAction.UPDATE: 0.3,
            ReconciliationAction.ROLLBACK: 0.5,
            ReconciliationAction.DELETE: 0.8,
        }.get(action, 0.3)

        # Increase risk for sensitive drift types
        if item.drift_type == DriftType.SECRET_DRIFT:
            base_risk = min(base_risk + 0.3, 1.0)
        elif item.drift_type == DriftType.POLICY_DRIFT:
            base_risk = min(base_risk + 0.2, 1.0)

        # Increase risk for critical severity
        if item.severity == "critical":
            base_risk = min(base_risk + 0.2, 1.0)

        return base_risk

    async def _execute_action(self, item: DriftItem, action: ReconciliationAction) -> None:
        """Execute a single reconciliation action against infrastructure."""
        if self._router is None:
            raise RuntimeError("No connector router available for applying changes")

        connector = self._router.get("kubernetes")

        if action == ReconciliationAction.CREATE or action == ReconciliationAction.UPDATE:
            await connector.apply_manifest(item.resource_id, item.expected_value)  # type: ignore[attr-defined]
        elif action == ReconciliationAction.DELETE:
            await connector.delete_resource(item.resource_id)  # type: ignore[attr-defined]
        elif action == ReconciliationAction.ROLLBACK:
            await connector.rollback(item.resource_id)
