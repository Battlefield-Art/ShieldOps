"""ShieldOps CrewAI integration — wraps CrewAI agents and crews with firewall interception."""

from __future__ import annotations

import functools
import time
from typing import Any

import structlog

from shieldops.sdk.config import SDKConfig
from shieldops.sdk.interceptor import ShieldOpsInterceptor

logger = structlog.get_logger()


class ShieldOpsCrewAIWrapper:
    """Wraps CrewAI agents with ShieldOps interception.

    Usage::

        from shieldops.sdk.crewai import ShieldOpsCrewAIWrapper
        from shieldops.sdk.config import SDKConfig

        wrapper = ShieldOpsCrewAIWrapper(SDKConfig(api_key="sk-...", mode="enforce"))
        secured_agent = wrapper.wrap_agent(my_crewai_agent)
        secured_crew = wrapper.wrap_crew(my_crew)
    """

    def __init__(self, config: SDKConfig) -> None:
        self._config = config
        self._interceptor = ShieldOpsInterceptor(config)
        logger.info(
            "shieldops_crewai.initialized",
            mode=config.mode.value,
            agent_id=config.agent_id,
        )

    def wrap_agent(self, agent: Any) -> Any:
        """Wrap a CrewAI agent so every tool call passes through ShieldOps interception.

        Monkey-patches the agent's ``execute_task`` method (or equivalent callable)
        to intercept tool invocations before they run.
        """
        interceptor = self._interceptor

        if hasattr(agent, "execute_task"):
            original_execute = agent.execute_task

            @functools.wraps(original_execute)
            def wrapped_execute(task: Any, *args: Any, **kwargs: Any) -> Any:
                tool_name = getattr(task, "tool", None) or getattr(task, "name", "crewai_task")
                task_args = {"description": str(getattr(task, "description", ""))[:500]}
                result = interceptor.intercept(str(tool_name), task_args)

                if result.decision == "block":
                    logger.warning(
                        "shieldops_crewai.task_blocked",
                        tool_name=str(tool_name),
                        reasons=result.reasons,
                    )
                    raise PermissionError(
                        f"ShieldOps blocked task '{tool_name}': {', '.join(result.reasons)}"
                    )

                start = time.time()
                try:
                    output = original_execute(task, *args, **kwargs)
                except Exception:
                    latency_ms = (time.time() - start) * 1000
                    interceptor.record(
                        tool_name=str(tool_name),
                        result_summary="ERROR",
                        latency_ms=latency_ms,
                        decision="error",
                    )
                    raise
                latency_ms = (time.time() - start) * 1000
                interceptor.record(
                    tool_name=str(tool_name),
                    result_summary=str(output)[:500],
                    latency_ms=latency_ms,
                )
                return output

            agent.execute_task = wrapped_execute

        # Also wrap individual tools if agent has a tools list
        if hasattr(agent, "tools") and isinstance(agent.tools, list):
            agent.tools = [self._wrap_tool(t) for t in agent.tools]

        logger.info("shieldops_crewai.agent_wrapped", agent=str(getattr(agent, "role", agent)))
        return agent

    def wrap_crew(self, crew: Any) -> Any:
        """Wrap all agents in a CrewAI crew with ShieldOps interception."""
        if hasattr(crew, "agents") and isinstance(crew.agents, list):
            for i, agent in enumerate(crew.agents):
                crew.agents[i] = self.wrap_agent(agent)
        logger.info(
            "shieldops_crewai.crew_wrapped",
            agent_count=len(getattr(crew, "agents", [])),
        )
        return crew

    def _wrap_tool(self, tool: Any) -> Any:
        """Wrap an individual CrewAI tool with interception."""
        interceptor = self._interceptor

        if hasattr(tool, "_run"):
            original_run = tool._run

            @functools.wraps(original_run)
            def wrapped_run(*args: Any, **kwargs: Any) -> Any:
                tool_name = getattr(tool, "name", str(tool))
                result = interceptor.intercept(tool_name, kwargs)
                if result.decision == "block":
                    raise PermissionError(
                        f"ShieldOps blocked tool '{tool_name}': {', '.join(result.reasons)}"
                    )
                start = time.time()
                output = original_run(*args, **kwargs)
                latency_ms = (time.time() - start) * 1000
                interceptor.record(
                    tool_name=tool_name,
                    result_summary=str(output)[:500],
                    latency_ms=latency_ms,
                )
                return output

            tool._run = wrapped_run

        return tool

    @property
    def interceptor(self) -> ShieldOpsInterceptor:
        return self._interceptor

    def get_audit_report(self) -> dict[str, Any]:
        return self._interceptor.get_audit_report()
