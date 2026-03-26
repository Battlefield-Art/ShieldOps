"""Zero Trust Network Access — Entry point and lifecycle management."""

from __future__ import annotations

from typing import Any

import structlog

from .graph import build_graph
from .tools import ZeroTrustNetworkToolkit

logger = structlog.get_logger()


class ZeroTrustNetworkRunner:
    """Runs the Zero Trust Network Access workflow."""

    def __init__(
        self,
        policy_engine: Any | None = None,
        identity_store: Any | None = None,
        alert_sink: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = ZeroTrustNetworkToolkit(
            policy_engine=policy_engine,
            identity_store=identity_store,
            alert_sink=alert_sink,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("zero_trust_network_runner.init")

    async def enforce(
        self,
        tenant_id: str,
        scope: str = "full",
        identity_filter: str = "",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full ZTNA enforcement workflow.

        Args:
            tenant_id: Tenant identifier.
            scope: Discovery scope (full, api, mcp).
            identity_filter: Filter identities by type.
            context: Additional context for the run.

        Returns:
            Final state with zero trust assessment.
        """
        context = context or {}

        initial_state: dict[str, Any] = {
            "tenant_id": tenant_id,
            "scope": scope,
            "identity_filter": identity_filter,
            "reasoning_chain": [],
        }

        logger.info(
            "zero_trust_network_runner.enforce",
            tenant_id=tenant_id,
            scope=scope,
            identity_filter=identity_filter,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("zero_trust_network_runner.enforce.error")
            raise

    async def assess_identity(
        self,
        tenant_id: str,
        identity_id: str,
        identity_type: str = "human",
        identity_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Assess trust for a single identity.

        Quick path for real-time identity verification
        without running the full workflow.
        """
        logger.info(
            "zero_trust_network_runner.assess_identity",
            tenant_id=tenant_id,
            identity_id=identity_id,
        )
        from .models import IdentityType

        id_type = IdentityType(identity_type)
        score = await self._toolkit.assess_identity_trust(
            identity_id=identity_id,
            identity_type=id_type,
            context=identity_context or {},
        )
        return score.model_dump()

    async def check_access(
        self,
        identity_id: str,
        access_point_id: str,
        trust_score: float,
        device_compliant: bool = True,
    ) -> dict[str, Any]:
        """Check access for a single request.

        Real-time policy enforcement for individual
        access requests.
        """
        logger.info(
            "zero_trust_network_runner.check_access",
            identity_id=identity_id,
            access_point_id=access_point_id,
        )
        enforcement = await self._toolkit.enforce_policy(
            identity_id=identity_id,
            access_point_id=access_point_id,
            trust_score=trust_score,
            device_compliant=device_compliant,
        )
        return enforcement.model_dump()

    async def _persist(
        self,
        result: dict[str, Any],
    ) -> None:
        """Persist ZTNA results to repository."""
        try:
            if hasattr(self._repository, "save"):
                await self._repository.save("zero_trust_network", result)
        except Exception:
            logger.exception("zero_trust_network_runner.persist.error")
