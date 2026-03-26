"""ShieldOps OpenAI Agents SDK Integration — intercept OpenAI Agents SDK tool calls."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.sdk.config import SDKConfig, SDKMode
from shieldops.sdk.interceptor import ShieldOpsInterceptor

logger = structlog.get_logger()


class ShieldOpsOpenAIAgentsHandler:
    """Intercepts OpenAI Agents SDK function calls through ShieldOps firewall.

    Provides ``on_function_call`` / ``on_function_result`` hooks that integrate
    with the OpenAI Agents SDK lifecycle for audit and enforcement.

    Usage::

        from shieldops.sdk.openai_agents import ShieldOpsOpenAIAgentsHandler

        handler = ShieldOpsOpenAIAgentsHandler(
            api_key="sk-...",
            mode="enforce",
            agent_id="my-openai-agent",
        )
        # Before executing a function call:
        handler.on_function_call("search_web", {"query": "..."})
        # After function returns:
        handler.on_function_result("search_web", result)
    """

    def __init__(
        self,
        api_key: str = "",
        endpoint: str = "https://api.shieldops.io",
        mode: str = "audit",
        agent_id: str = "openai-agent",
    ) -> None:
        config = SDKConfig(
            api_key=api_key,
            endpoint=endpoint,
            mode=SDKMode(mode),
            agent_id=agent_id,
        )
        self._config = config
        self._interceptor = ShieldOpsInterceptor(config)
        self._agent_id = agent_id
        self._pending_calls: dict[str, float] = {}
        logger.info(
            "shieldops_openai_agents.initialized",
            agent_id=agent_id,
            mode=mode,
        )

    # -- Function call interception -------------------------------------------

    def on_function_call(
        self,
        function_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        call_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Intercept an OpenAI Agents SDK function call before execution.

        Returns a dict with ``decision`` and ``risk_score``.
        Raises ``PermissionError`` if the function is blocked in enforce mode.
        """
        call_key = call_id or function_name
        self._pending_calls[call_key] = time.time()

        args = arguments or {}
        result = self._interceptor.intercept(
            function_name,
            args,
            agent_id=self._agent_id,
        )

        if result.decision == "block":
            logger.warning(
                "shieldops_openai_agents.function_blocked",
                function_name=function_name,
                risk_score=result.risk_score,
                reasons=result.reasons,
            )
            raise PermissionError(
                f"ShieldOps blocked function '{function_name}': "
                f"{', '.join(result.reasons)}"
            )

        logger.info(
            "shieldops_openai_agents.function_start",
            function_name=function_name,
            risk_score=result.risk_score,
        )
        return {"decision": result.decision, "risk_score": result.risk_score}

    def on_function_result(
        self,
        function_name: str,
        result: Any,
        *,
        call_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Record function result after execution."""
        call_key = call_id or function_name
        start = self._pending_calls.pop(call_key, time.time())
        latency_ms = (time.time() - start) * 1000

        self._interceptor.record(
            tool_name=function_name,
            result_summary=str(result)[:500],
            latency_ms=latency_ms,
        )

    def on_function_error(
        self,
        function_name: str,
        error: BaseException,
        *,
        call_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Record function errors."""
        call_key = call_id or function_name
        start = self._pending_calls.pop(call_key, time.time())
        latency_ms = (time.time() - start) * 1000

        self._interceptor.record(
            tool_name=function_name,
            result_summary=f"ERROR: {error!s}"[:500],
            latency_ms=latency_ms,
            decision="error",
        )
        logger.error(
            "shieldops_openai_agents.function_error",
            function_name=function_name,
            error=str(error),
        )

    # -- Handoff auditing -----------------------------------------------------

    def on_handoff(
        self,
        from_agent: str,
        to_agent: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Audit agent handoff events in multi-agent workflows."""
        self._interceptor.intercept(
            tool_name=f"openai:handoff:{from_agent}->{to_agent}",
            args={"from": from_agent, "to": to_agent},
            agent_id=self._agent_id,
        )
        self._interceptor.record(
            tool_name=f"openai:handoff:{from_agent}->{to_agent}",
            result_summary=f"Handoff from {from_agent} to {to_agent}",
        )
        logger.debug(
            "shieldops_openai_agents.handoff_audited",
            from_agent=from_agent,
            to_agent=to_agent,
        )

    # -- Accessors ------------------------------------------------------------

    @property
    def interceptor(self) -> ShieldOpsInterceptor:
        """Access the underlying interceptor for reports and flushing."""
        return self._interceptor

    def get_stats(self) -> dict[str, Any]:
        """Return interception statistics."""
        return self._interceptor.get_audit_report()

    def get_audit_report(self) -> dict[str, Any]:
        return self._interceptor.get_audit_report()
