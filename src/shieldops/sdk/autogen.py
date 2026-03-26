"""ShieldOps AutoGen Integration — wrapper for Microsoft AutoGen agents."""

from __future__ import annotations

import functools
import time
from typing import Any

import structlog

from shieldops.sdk.config import SDKConfig, SDKMode
from shieldops.sdk.interceptor import ShieldOpsInterceptor

logger = structlog.get_logger()


class ShieldOpsAutoGenWrapper:
    """Wraps Microsoft AutoGen agents with ShieldOps firewall interception.

    Intercepts tool execution and message flow for audit and enforcement.

    Usage::

        from shieldops.sdk.autogen import ShieldOpsAutoGenWrapper

        wrapper = ShieldOpsAutoGenWrapper(
            api_key="sk-...",
            mode="enforce",
            agent_id="my-autogen-agent",
        )
        secured_agent = wrapper.wrap_agent(my_autogen_agent)
    """

    def __init__(
        self,
        api_key: str = "",
        endpoint: str = "https://api.shieldops.io",
        mode: str = "audit",
        agent_id: str = "autogen-agent",
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
        self._pending_tools: dict[str, float] = {}
        logger.info(
            "shieldops_autogen.initialized",
            agent_id=agent_id,
            mode=mode,
        )

    # -- Tool interception ----------------------------------------------------

    def wrap_tool_execution(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Evaluate a tool call against ShieldOps policy before execution.

        Returns a dict with ``decision`` and ``risk_score``.
        Raises ``PermissionError`` if the tool is blocked in enforce mode.
        """
        args = tool_args or {}
        self._pending_tools[tool_name] = time.time()

        result = self._interceptor.intercept(
            tool_name,
            args,
            agent_id=self._agent_id,
        )

        if result.decision == "block":
            logger.warning(
                "shieldops_autogen.tool_blocked",
                tool_name=tool_name,
                risk_score=result.risk_score,
                reasons=result.reasons,
            )
            raise PermissionError(
                f"ShieldOps blocked tool '{tool_name}': "
                f"{', '.join(result.reasons)}"
            )

        logger.info(
            "shieldops_autogen.tool_start",
            tool_name=tool_name,
            risk_score=result.risk_score,
        )
        return {"decision": result.decision, "risk_score": result.risk_score}

    def record_tool_result(
        self,
        tool_name: str,
        output: Any,
    ) -> None:
        """Record tool execution completion."""
        start = self._pending_tools.pop(tool_name, time.time())
        latency_ms = (time.time() - start) * 1000

        self._interceptor.record(
            tool_name=tool_name,
            result_summary=str(output)[:500],
            latency_ms=latency_ms,
        )

    # -- Message auditing -----------------------------------------------------

    def on_message(
        self,
        sender: str,
        message: str | dict[str, Any],
    ) -> None:
        """Audit message flow between AutoGen agents."""
        msg_str = str(message)
        self._interceptor.intercept(
            tool_name=f"autogen:message:{sender}",
            args={"message_chars": len(msg_str), "sender": sender},
            agent_id=self._agent_id,
        )
        self._interceptor.record(
            tool_name=f"autogen:message:{sender}",
            result_summary=msg_str[:500],
        )
        logger.debug(
            "shieldops_autogen.message_audited",
            sender=sender,
            message_len=len(msg_str),
        )

    # -- Agent wrapping -------------------------------------------------------

    def wrap_agent(self, agent: Any) -> Any:
        """Wrap an AutoGen agent so tool calls pass through ShieldOps.

        Monkey-patches ``generate_reply`` and ``execute_function`` if present.
        """
        interceptor = self._interceptor
        agent_id = self._agent_id

        if hasattr(agent, "execute_function"):
            original_exec = agent.execute_function

            @functools.wraps(original_exec)
            def wrapped_exec(func_call: dict[str, Any], **kwargs: Any) -> Any:
                tool_name = func_call.get("name", "unknown_function")
                tool_args = func_call.get("arguments", {})
                result = interceptor.intercept(tool_name, tool_args, agent_id=agent_id)

                if result.decision == "block":
                    logger.warning(
                        "shieldops_autogen.function_blocked",
                        tool_name=tool_name,
                        reasons=result.reasons,
                    )
                    raise PermissionError(
                        f"ShieldOps blocked function '{tool_name}': "
                        f"{', '.join(result.reasons)}"
                    )

                start = time.time()
                try:
                    output = original_exec(func_call, **kwargs)
                except Exception:
                    latency_ms = (time.time() - start) * 1000
                    interceptor.record(
                        tool_name=tool_name,
                        result_summary="ERROR",
                        latency_ms=latency_ms,
                        decision="error",
                    )
                    raise
                latency_ms = (time.time() - start) * 1000
                interceptor.record(
                    tool_name=tool_name,
                    result_summary=str(output)[:500],
                    latency_ms=latency_ms,
                )
                return output

            agent.execute_function = wrapped_exec

        logger.info(
            "shieldops_autogen.agent_wrapped",
            agent=str(getattr(agent, "name", agent)),
        )
        return agent

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
