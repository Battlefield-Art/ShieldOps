"""LLM Prompt Firewall Agent runner — entry point
for executing prompt injection defense."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.llm_prompt_firewall.graph import (
    create_llm_prompt_firewall_graph,
)
from shieldops.agents.llm_prompt_firewall.models import (
    LLMPromptFirewallState,
)
from shieldops.agents.llm_prompt_firewall.nodes import (
    set_toolkit,
)
from shieldops.agents.llm_prompt_firewall.tools import (
    LLMPromptFirewallToolkit,
)

logger = structlog.get_logger()


class LLMPromptFirewallRunner:
    """Runner for the LLM Prompt Firewall Agent."""

    def __init__(
        self,
        pattern_db: Any | None = None,
        intent_analyzer: Any | None = None,
        injection_detector: Any | None = None,
        risk_classifier: Any | None = None,
        enforcement_engine: Any | None = None,
        metrics_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = LLMPromptFirewallToolkit(
            pattern_db=pattern_db,
            intent_analyzer=intent_analyzer,
            injection_detector=injection_detector,
            risk_classifier=risk_classifier,
            enforcement_engine=enforcement_engine,
            metrics_store=metrics_store,
            repository=repository,
        )
        set_toolkit(self._toolkit)
        graph = create_llm_prompt_firewall_graph()
        self._app = graph.compile()
        self._results: dict[str, LLMPromptFirewallState] = {}
        logger.info("lpf_runner.initialized")

    async def analyze(
        self,
        prompts: list[dict[str, Any]],
        known_patterns: list[str] | None = None,
        policy_config: dict[str, Any] | None = None,
        tenant_id: str = "",
    ) -> LLMPromptFirewallState:
        """Run prompt firewall analysis on a batch."""
        request_id = f"lpf-{uuid4().hex[:12]}"

        initial_state = LLMPromptFirewallState(
            request_id=request_id,
            tenant_id=tenant_id,
            prompts=prompts,
            known_patterns=known_patterns or [],
            policy_config=policy_config or {},
        )

        logger.info(
            "lpf_runner.starting",
            request_id=request_id,
            prompts=len(prompts),
        )

        try:
            result = await self._app.ainvoke(
                initial_state.model_dump(),  # type: ignore[arg-type]
                config={
                    "metadata": {
                        "request_id": request_id,
                        "agent": "llm_prompt_firewall",
                    },
                },
            )
            final = LLMPromptFirewallState.model_validate(
                result,
            )
            self._results[request_id] = final

            logger.info(
                "lpf_runner.completed",
                request_id=request_id,
                intercepted=final.total_intercepted,
                injections=final.injections_detected,
                blocked=final.prompts_blocked,
                sanitized=final.prompts_sanitized,
                duration_ms=final.session_duration_ms,
            )
            return final

        except Exception as e:
            logger.error(
                "lpf_runner.failed",
                request_id=request_id,
                error=str(e),
            )
            error_state = LLMPromptFirewallState(
                request_id=request_id,
                tenant_id=tenant_id,
                prompts=prompts,
                error=str(e),
                current_step="failed",
            )
            self._results[request_id] = error_state
            return error_state

    def get_result(
        self,
        request_id: str,
    ) -> LLMPromptFirewallState | None:
        """Retrieve a cached analysis result."""
        return self._results.get(request_id)

    def list_results(self) -> list[dict[str, Any]]:
        """List all analysis results as summaries."""
        return [
            {
                "request_id": rid,
                "total_intercepted": s.total_intercepted,
                "injections_detected": s.injections_detected,
                "blocked": s.prompts_blocked,
                "sanitized": s.prompts_sanitized,
                "current_step": s.current_step,
                "error": s.error,
            }
            for rid, s in self._results.items()
        ]
