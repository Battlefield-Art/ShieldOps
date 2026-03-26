"""AI SOC Assistant Agent runner — entry point for NL investigation."""

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.ai_soc_assistant.graph import (
    create_ai_soc_assistant_graph,
)
from shieldops.agents.ai_soc_assistant.models import (
    AISOCAssistantState,
)
from shieldops.agents.ai_soc_assistant.nodes import (
    set_toolkit,
)
from shieldops.agents.ai_soc_assistant.tools import (
    AISOCAssistantToolkit,
)

logger = structlog.get_logger()


class AISOCAssistantRunner:
    """Runner for the AI SOC Assistant Agent."""

    def __init__(
        self,
        splunk_connector: Any | None = None,
        elastic_connector: Any | None = None,
        crowdstrike_connector: Any | None = None,
        defender_connector: Any | None = None,
        okta_connector: Any | None = None,
        soar_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AISOCAssistantToolkit(
            splunk_connector=splunk_connector,
            elastic_connector=elastic_connector,
            crowdstrike_connector=crowdstrike_connector,
            defender_connector=defender_connector,
            okta_connector=okta_connector,
            soar_engine=soar_engine,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_ai_soc_assistant_graph()
        self._app = graph.compile()
        self._results: dict[str, AISOCAssistantState] = {}
        self._conversations: dict[str, list[str]] = {}
        logger.info("ai_soc_assistant_runner.initialized")

    async def ask(
        self,
        tenant_id: str,
        query: str,
        conversation_id: str | None = None,
    ) -> AISOCAssistantState:
        """Run the AI SOC assistant on an analyst query.

        Args:
            tenant_id: Tenant identifier.
            query: Natural language query from analyst.
            conversation_id: Optional ID for follow-ups.

        Returns:
            Final AISOCAssistantState with response.
        """
        session_id = f"assist-{uuid4().hex[:12]}"
        conv_id = conversation_id or session_id

        # Track conversation history
        if conv_id not in self._conversations:
            self._conversations[conv_id] = []
        self._conversations[conv_id].append(query)

        # Get prior query count for avg calculation
        prior_count = sum(1 for s in self._results.values() if s.tenant_id == tenant_id)
        prior_avg = 0.0
        if prior_count > 0:
            prior_results = [s for s in self._results.values() if s.tenant_id == tenant_id]
            prior_avg = sum(s.avg_response_time_seconds for s in prior_results) / len(prior_results)

        initial_state = AISOCAssistantState(
            tenant_id=tenant_id,
            query=query,
            conversation_id=conv_id,
            queries_handled=prior_count,
            avg_response_time_seconds=prior_avg,
        )

        logger.info(
            "ai_soc_assistant_runner.starting",
            session_id=session_id,
            tenant_id=tenant_id,
            query=query[:80],
            conversation_id=conv_id,
        )

        try:
            final_dict = await self._app.ainvoke(
                initial_state.model_dump(),
                config={
                    "metadata": {
                        "session_id": session_id,
                        "agent": "ai_soc_assistant",
                        "tenant_id": tenant_id,
                    },
                },
            )
            final_state = AISOCAssistantState.model_validate(
                final_dict,
            )
            self._results[session_id] = final_state

            logger.info(
                "ai_soc_assistant_runner.completed",
                session_id=session_id,
                risk_level=(
                    final_state.reasoning.risk_level if final_state.reasoning else "unknown"
                ),
                actions=len(
                    final_state.suggested_actions,
                ),
                queries_handled=(final_state.queries_handled),
            )
            return final_state

        except Exception as e:
            logger.error(
                "ai_soc_assistant_runner.failed",
                session_id=session_id,
                error=str(e),
            )
            error_state = AISOCAssistantState(
                tenant_id=tenant_id,
                query=query,
                conversation_id=conv_id,
                error=str(e),
                current_step="failed",
            )
            self._results[session_id] = error_state
            return error_state

    def get_result(
        self,
        session_id: str,
    ) -> AISOCAssistantState | None:
        """Get result by session ID."""
        return self._results.get(session_id)

    def get_conversation(
        self,
        conversation_id: str,
    ) -> list[str]:
        """Get conversation history."""
        return self._conversations.get(
            conversation_id,
            [],
        )

    def list_results(self) -> list[dict[str, Any]]:
        """List all session results."""
        return [
            {
                "session_id": sid,
                "tenant_id": state.tenant_id,
                "query": state.query[:60],
                "risk_level": (state.reasoning.risk_level if state.reasoning else "unknown"),
                "actions": len(
                    state.suggested_actions,
                ),
                "current_step": state.current_step,
                "error": state.error,
            }
            for sid, state in self._results.items()
        ]
