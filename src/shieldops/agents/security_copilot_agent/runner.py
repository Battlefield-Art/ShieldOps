"""Security Copilot Agent runner — entry point for
interactive security analyst assistance."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.security_copilot_agent.graph import (
    create_security_copilot_agent_graph,
)
from shieldops.agents.security_copilot_agent.models import (
    SecurityCopilotAgentState,
)
from shieldops.agents.security_copilot_agent.nodes import (
    set_toolkit,
)
from shieldops.agents.security_copilot_agent.tools import (
    SecurityCopilotAgentToolkit,
)

logger = structlog.get_logger()


class SecurityCopilotAgentRunner:
    """Runner for the Security Copilot Agent."""

    def __init__(
        self,
        query_parser: Any | None = None,
        context_engine: Any | None = None,
        threat_intel: Any | None = None,
        action_engine: Any | None = None,
        knowledge_store: Any | None = None,
        metrics_collector: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = SecurityCopilotAgentToolkit(
            query_parser=query_parser,
            context_engine=context_engine,
            threat_intel=threat_intel,
            action_engine=action_engine,
            knowledge_store=knowledge_store,
            metrics_collector=metrics_collector,
            policy_engine=policy_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_security_copilot_agent_graph()
        self._app = graph.compile()
        self._results: dict[str, SecurityCopilotAgentState] = {}
        logger.info("sca_runner.initialized")

    async def ask(
        self,
        raw_query: str,
        analyst_id: str = "",
        session_history: list[dict[str, Any]] | None = None,
        tenant_id: str = "",
    ) -> SecurityCopilotAgentState:
        """Run an interactive security copilot session."""
        request_id = f"sca-{uuid4().hex[:12]}"

        initial_state = SecurityCopilotAgentState(
            request_id=request_id,
            tenant_id=tenant_id,
            raw_query=raw_query,
            analyst_id=analyst_id,
            session_history=session_history or [],
        )

        logger.info(
            "sca_runner.starting",
            request_id=request_id,
            query_len=len(raw_query),
            analyst_id=analyst_id,
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "security_copilot_agent",
                    },
                },
            )
            final = SecurityCopilotAgentState.model_validate(result)
            self._results[request_id] = final

            logger.info(
                "sca_runner.completed",
                request_id=request_id,
                resolved=final.query_resolved,
                actions=final.actions_taken,
                confidence=final.confidence_score,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "sca_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = SecurityCopilotAgentState(
                request_id=request_id,
                tenant_id=tenant_id,
                raw_query=raw_query,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> SecurityCopilotAgentState | None:
        """Retrieve a cached session result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all session results as summaries."""
        return [
            {
                "request_id": rid,
                "query": s.raw_query[:80],
                "resolved": s.query_resolved,
                "actions_taken": s.actions_taken,
                "confidence": s.confidence_score,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
