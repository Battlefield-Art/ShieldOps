"""GitOps Agent runner — entry point for executing reconciliation workflows.

Takes repository details, constructs the LangGraph, runs it end-to-end,
and returns the completed GitOps state.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.gitops.graph import create_gitops_graph
from shieldops.agents.gitops.models import GitOpsState
from shieldops.agents.gitops.nodes import set_toolkit
from shieldops.agents.gitops.tools import GitOpsToolkit
from shieldops.connectors.base import ConnectorRouter
from shieldops.licensing.enforce import enforced

if __import__("typing").TYPE_CHECKING:
    from shieldops.db.repository import Repository

logger = structlog.get_logger()


class GitOpsRunner:
    """Runs GitOps reconciliation agent workflows.

    Usage:
        runner = GitOpsRunner(connector_router=router)
        result = await runner.run(
            repo_url="https://github.com/org/infra",
            branch="main",
            namespace="production",
            dry_run=True,
        )
    """

    def __init__(
        self,
        connector_router: ConnectorRouter | None = None,
        repository: "Repository | None" = None,
    ) -> None:
        self._toolkit = GitOpsToolkit(
            connector_router=connector_router,
            repository=repository,
        )
        # Configure the module-level toolkit for nodes
        set_toolkit(self._toolkit)

        # Build the compiled graph
        graph = create_gitops_graph()
        self._app = graph.compile()

        # In-memory store of completed reconciliations (fallback when no DB)
        self._reconciliations: dict[str, GitOpsState] = {}
        self._repository = repository

    @enforced("gitops")
    async def run(
        self,
        repo_url: str,
        branch: str = "main",
        namespace: str = "",
        dry_run: bool = True,
    ) -> GitOpsState:
        """Run a full GitOps reconciliation workflow.

        Args:
            repo_url: URL of the Git repository containing desired state.
            branch: Git branch to use for desired state.
            namespace: Kubernetes namespace to reconcile (empty for all).
            dry_run: If True, simulate changes without applying.

        Returns:
            The completed GitOpsState with drift analysis and results.
        """
        request_id = f"gitops-{uuid4().hex[:12]}"

        logger.info(
            "gitops_run_started",
            request_id=request_id,
            repo_url=repo_url,
            branch=branch,
            namespace=namespace,
            dry_run=dry_run,
        )

        initial_state = GitOpsState(
            request_id=request_id,
            repo_url=repo_url,
            branch=branch,
            namespace=namespace,
            dry_run=dry_run,
        )

        try:
            final_state_dict = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "repo_url": repo_url,
                    },
                },
            )

            final_state = GitOpsState.model_validate(final_state_dict)

            # Calculate total duration
            if final_state.started_at:
                final_state.duration_ms = int(
                    (datetime.now(UTC) - final_state.started_at).total_seconds() * 1000
                )

            logger.info(
                "gitops_run_completed",
                request_id=request_id,
                drift_count=len(final_state.drift_items),
                apply_count=len(final_state.apply_results),
                verification=final_state.verification_passed,
                duration_ms=final_state.duration_ms,
            )

            # Store result
            self._reconciliations[request_id] = final_state
            await self._persist(request_id, final_state)
            return final_state

        except Exception as e:
            logger.error(
                "gitops_run_failed",
                request_id=request_id,
                repo_url=repo_url,
                error=str(e),
            )
            error_state = GitOpsState(
                request_id=request_id,
                repo_url=repo_url,
                branch=branch,
                namespace=namespace,
                dry_run=dry_run,
                error=str(e),
                current_step="failed",
            )
            self._reconciliations[request_id] = error_state
            await self._persist(request_id, error_state)
            return error_state

    async def _persist(self, request_id: str, state: GitOpsState) -> None:
        """Persist to DB if repository is available."""
        if self._repository is None:
            return
        try:
            await self._repository.save_gitops_reconciliation(request_id, state)  # type: ignore[attr-defined]
        except Exception as e:
            logger.error("gitops_persist_failed", id=request_id, error=str(e))

    def get_reconciliation(self, request_id: str) -> GitOpsState | None:
        """Retrieve a completed reconciliation by ID."""
        return self._reconciliations.get(request_id)

    def list_reconciliations(self) -> list[dict[str, Any]]:
        """List all reconciliations with summary info."""
        return [
            {
                "request_id": req_id,
                "repo_url": state.repo_url,
                "branch": state.branch,
                "namespace": state.namespace,
                "status": state.current_step,
                "drift_count": len(state.drift_items),
                "apply_count": len(state.apply_results),
                "verification": state.verification_passed,
                "dry_run": state.dry_run,
                "duration_ms": state.duration_ms,
                "error": state.error,
            }
            for req_id, state in self._reconciliations.items()
        ]
