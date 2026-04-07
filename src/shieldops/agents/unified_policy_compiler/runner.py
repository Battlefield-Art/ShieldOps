"""Unified Policy Compiler runner — entry point."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.unified_policy_compiler.graph import (
    create_unified_policy_compiler_graph,
)
from shieldops.agents.unified_policy_compiler.models import (
    UnifiedPolicyCompilerState,
)
from shieldops.agents.unified_policy_compiler.nodes import (
    set_toolkit,
)
from shieldops.agents.unified_policy_compiler.tools import (
    UnifiedPolicyCompilerToolkit,
)
from shieldops.licensing.enforce import enforced

logger = structlog.get_logger()


class UnifiedPolicyCompilerRunner:
    """Runner for the Unified Policy Compiler Agent."""

    def __init__(
        self,
        policy_store: Any | None = None,
        opa_client: Any | None = None,
        compliance_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = UnifiedPolicyCompilerToolkit(
            policy_store=policy_store,
            opa_client=opa_client,
            compliance_engine=compliance_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_unified_policy_compiler_graph()
        self._app = graph.compile()
        self._results: dict[str, UnifiedPolicyCompilerState] = {}
        logger.info("upc_runner.initialized")

    @enforced("unified_policy_compiler")
    async def run(
        self,
        request_id: str,
        tenant_id: str = "",
        config: dict[str, Any] | None = None,
    ) -> UnifiedPolicyCompilerState:
        """Run policy compilation workflow."""
        sid = f"upc-{uuid4().hex[:12]}"
        initial = UnifiedPolicyCompilerState(
            request_id=request_id,
            tenant_id=tenant_id,
            config=config or {},
        )

        logger.info(
            "upc_runner.starting",
            session_id=sid,
            request_id=request_id,
        )

        try:
            result = await self._app.ainvoke(
                initial.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "session_id": sid,
                        "agent": "unified_policy_compiler",
                    },
                },
            )
            final = UnifiedPolicyCompilerState.model_validate(
                result,
            )
            self._results[sid] = final

            logger.info(
                "upc_runner.completed",
                session_id=sid,
                policies=len(final.policy_records),
                rules=len(final.compiled_rules),
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "upc_runner.failed",
                session_id=sid,
                error=str(e),
            )
            err_state = UnifiedPolicyCompilerState(
                request_id=request_id,
                tenant_id=tenant_id,
                config=config or {},
                error=str(e),
                current_step="failed",
            )
            self._results[sid] = err_state
            return err_state

    def get_result(
        self,
        session_id: str,
    ) -> UnifiedPolicyCompilerState | None:
        """Retrieve a previous result."""
        return self._results.get(session_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all results."""
        return [
            {
                "session_id": sid,
                "request_id": s.request_id,
                "policies": len(s.policy_records),
                "rules": len(s.compiled_rules),
                "step": s.current_step,
                "error": s.error,
            }
            for sid, s in self._results.items()
        ]
