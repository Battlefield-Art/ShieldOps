"""ShieldOps LangChain integration — callback handler for agent firewall interception."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.sdk.config import SDKConfig, SDKMode
from shieldops.sdk.interceptor import ShieldOpsInterceptor

logger = structlog.get_logger()


class ShieldOpsCallbackHandler:
    """LangChain callback handler that intercepts tool and LLM calls with ShieldOps.

    Drop-in replacement for ``langchain_core.callbacks.BaseCallbackHandler``.
    Inheriting from LangChain's base class is optional — this implements the
    same interface so it works with or without langchain installed.

    Usage::

        from shieldops.sdk.langchain import ShieldOpsCallbackHandler

        handler = ShieldOpsCallbackHandler(
            api_key="sk-...",
            mode="enforce",
            agent_id="my-research-agent",
        )
        # Pass as callback to any LangChain chain / agent
        agent.invoke({"input": "..."}, config={"callbacks": [handler]})
    """

    def __init__(
        self,
        api_key: str = "",
        endpoint: str = "https://api.shieldops.io",
        mode: str = "audit",
        agent_id: str | None = None,
    ) -> None:
        config = SDKConfig(
            api_key=api_key,
            endpoint=endpoint,
            mode=SDKMode(mode),
            agent_id=agent_id,
        )
        self._interceptor = ShieldOpsInterceptor(config)
        self._pending_tools: dict[str, float] = {}  # run_id -> start time
        self._pending_llms: dict[str, float] = {}
        logger.info(
            "shieldops_langchain.initialized",
            mode=mode,
            agent_id=agent_id,
        )

    # -- Tool callbacks -------------------------------------------------------

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Intercept before tool execution."""
        tool_name = serialized.get("name", serialized.get("id", ["unknown"])[-1])
        run_key = run_id or tool_name
        self._pending_tools[run_key] = time.time()

        args = {"input": input_str[:1000]}
        result = self._interceptor.intercept(tool_name, args, agent_id=None)

        if result.decision == "block":
            logger.warning(
                "shieldops_langchain.tool_blocked",
                tool_name=tool_name,
                risk_score=result.risk_score,
                reasons=result.reasons,
            )
            raise PermissionError(
                f"ShieldOps blocked tool '{tool_name}': {', '.join(result.reasons)}"
            )

        logger.info(
            "shieldops_langchain.tool_start",
            tool_name=tool_name,
            risk_score=result.risk_score,
        )

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Record result after tool execution."""
        run_key = run_id or "unknown"
        start = self._pending_tools.pop(run_key, time.time())
        latency_ms = (time.time() - start) * 1000

        self._interceptor.record(
            tool_name=run_key,
            result_summary=str(output)[:500],
            latency_ms=latency_ms,
        )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Record tool errors."""
        run_key = run_id or "unknown"
        start = self._pending_tools.pop(run_key, time.time())
        latency_ms = (time.time() - start) * 1000

        self._interceptor.record(
            tool_name=run_key,
            result_summary=f"ERROR: {error!s}"[:500],
            latency_ms=latency_ms,
            decision="error",
        )
        logger.error(
            "shieldops_langchain.tool_error",
            tool_name=run_key,
            error=str(error),
        )

    # -- LLM callbacks --------------------------------------------------------

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Intercept LLM calls — log prompt metadata without capturing content."""
        model_name = serialized.get("id", ["unknown"])[-1] if serialized.get("id") else "unknown"
        run_key = run_id or model_name
        self._pending_llms[run_key] = time.time()

        self._interceptor.intercept(
            tool_name=f"llm:{model_name}",
            args={"prompt_count": len(prompts), "total_chars": sum(len(p) for p in prompts)},
        )

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Record LLM response metadata."""
        run_key = run_id or "unknown"
        start = self._pending_llms.pop(run_key, time.time())
        latency_ms = (time.time() - start) * 1000

        self._interceptor.record(
            tool_name=f"llm:{run_key}",
            result_summary="llm_response",
            latency_ms=latency_ms,
        )

    # -- Accessors ------------------------------------------------------------

    @property
    def interceptor(self) -> ShieldOpsInterceptor:
        """Access the underlying interceptor for reports and flushing."""
        return self._interceptor

    def get_audit_report(self) -> dict[str, Any]:
        return self._interceptor.get_audit_report()
