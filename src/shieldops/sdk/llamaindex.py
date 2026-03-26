"""ShieldOps LlamaIndex Integration — intercept and audit LlamaIndex agent tool calls."""

from __future__ import annotations

import time
from typing import Any

import structlog

from shieldops.sdk.config import SDKConfig, SDKMode
from shieldops.sdk.interceptor import ShieldOpsInterceptor

logger = structlog.get_logger()


class ShieldOpsLlamaIndexHandler:
    """LlamaIndex callback handler that intercepts tool calls through ShieldOps.

    Drop-in callback handler for LlamaIndex agents. Implements the same
    ``on_tool_start`` / ``on_tool_end`` interface used by LlamaIndex's
    callback system so it works with or without ``llama-index`` installed.

    Usage::

        from shieldops.sdk.llamaindex import ShieldOpsLlamaIndexHandler

        handler = ShieldOpsLlamaIndexHandler(
            api_key="sk-...",
            mode="enforce",
            agent_id="my-rag-agent",
        )
        # Attach to LlamaIndex service context or agent
    """

    def __init__(
        self,
        api_key: str = "",
        endpoint: str = "https://api.shieldops.io",
        mode: str = "audit",
        agent_id: str = "llamaindex-agent",
    ) -> None:
        config = SDKConfig(
            api_key=api_key,
            endpoint=endpoint,
            mode=SDKMode(mode),
            agent_id=agent_id,
        )
        self._interceptor = ShieldOpsInterceptor(config)
        self._agent_id = agent_id
        self._pending_tools: dict[str, float] = {}
        logger.info(
            "shieldops_llamaindex.initialized",
            agent_id=agent_id,
            mode=mode,
        )

    # -- Tool callbacks -------------------------------------------------------

    def on_tool_start(
        self,
        tool_name: str,
        tool_input: dict[str, Any] | None = None,
        *,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Intercept tool call before execution."""
        run_key = run_id or tool_name
        self._pending_tools[run_key] = time.time()

        args = tool_input or {}
        result = self._interceptor.intercept(
            tool_name,
            args,
            agent_id=self._agent_id,
        )

        if result.decision == "block":
            logger.warning(
                "shieldops_llamaindex.tool_blocked",
                tool_name=tool_name,
                risk_score=result.risk_score,
                reasons=result.reasons,
            )
            raise PermissionError(
                f"ShieldOps blocked tool call: {tool_name} — "
                f"{', '.join(result.reasons)}"
            )

        logger.info(
            "shieldops_llamaindex.tool_start",
            tool_name=tool_name,
            risk_score=result.risk_score,
        )
        return {"decision": result.decision, "risk_score": result.risk_score}

    def on_tool_end(
        self,
        tool_name: str,
        output: Any,
        *,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Record tool call completion."""
        run_key = run_id or tool_name
        start = self._pending_tools.pop(run_key, time.time())
        latency_ms = (time.time() - start) * 1000

        self._interceptor.record(
            tool_name=tool_name,
            result_summary=str(output)[:500],
            latency_ms=latency_ms,
        )

    def on_tool_error(
        self,
        tool_name: str,
        error: BaseException,
        *,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Record tool errors."""
        run_key = run_id or tool_name
        start = self._pending_tools.pop(run_key, time.time())
        latency_ms = (time.time() - start) * 1000

        self._interceptor.record(
            tool_name=tool_name,
            result_summary=f"ERROR: {error!s}"[:500],
            latency_ms=latency_ms,
            decision="error",
        )
        logger.error(
            "shieldops_llamaindex.tool_error",
            tool_name=tool_name,
            error=str(error),
        )

    # -- Query engine callbacks -----------------------------------------------

    def on_query_start(
        self,
        query_str: str,
        *,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Intercept LlamaIndex query engine calls."""
        run_key = run_id or "query"
        self._pending_tools[run_key] = time.time()

        self._interceptor.intercept(
            tool_name="llamaindex:query",
            args={"query_chars": len(query_str)},
            agent_id=self._agent_id,
        )

    def on_query_end(
        self,
        response: Any,
        *,
        run_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Record query completion."""
        run_key = run_id or "query"
        start = self._pending_tools.pop(run_key, time.time())
        latency_ms = (time.time() - start) * 1000

        self._interceptor.record(
            tool_name="llamaindex:query",
            result_summary="query_response",
            latency_ms=latency_ms,
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
