"""Agent Behavioral Firewall — Entry point and lifecycle management."""

from __future__ import annotations

import time
from typing import Any

import structlog

from .graph import build_graph
from .models import MonitoringMode
from .tools import AgentFirewallToolkit

logger = structlog.get_logger()


class AgentFirewallRunner:
    """Runs the Agent Behavioral Firewall workflow."""

    def __init__(
        self,
        policy_engine: Any | None = None,
        event_store: Any | None = None,
        alert_sink: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._toolkit = AgentFirewallToolkit(
            policy_engine=policy_engine,
            event_store=event_store,
            alert_sink=alert_sink,
        )
        self._repository = repository
        self._graph = build_graph(self._toolkit)
        self._app = self._graph.compile()
        logger.info("agent_firewall_runner.init")

    async def monitor(
        self,
        agent_id: str,
        calls: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the full firewall monitoring workflow for an agent."""
        context = context or {}
        mode = context.get("monitoring_mode", MonitoringMode.AUDIT.value)
        policy_set = context.get("policy_set", {})
        window = context.get("time_window_minutes", 60)

        initial_state: dict[str, Any] = {
            "monitored_agent_id": agent_id,
            "monitoring_mode": mode,
            "policy_set": policy_set,
            "time_window_minutes": window,
            "intercepted_calls": calls,
            "reasoning_chain": [],
        }

        logger.info(
            "agent_firewall_runner.monitor",
            agent_id=agent_id,
            call_count=len(calls),
            mode=mode,
        )
        try:
            result = await self._app.ainvoke(initial_state)  # type: ignore[arg-type]
            if self._repository:
                await self._persist(result)
            return result
        except Exception:
            logger.exception("agent_firewall_runner.monitor.error")
            raise

    async def evaluate_call(
        self,
        agent_id: str,
        tool_call: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate a single tool call against firewall policies.

        This is the real-time interception entry point — called before
        each agent tool execution.
        """
        logger.info(
            "agent_firewall_runner.evaluate_call",
            agent_id=agent_id,
            tool_name=tool_call.get("tool_name", "unknown"),
        )
        start = time.time()

        # Intercept and risk-score the call
        intercepted = await self._toolkit.intercept_call(
            agent_id=agent_id,
            tool_name=tool_call.get("tool_name", "unknown"),
            args=tool_call.get("args", {}),
            data_volume=tool_call.get("data_volume", 0),
        )

        # Evaluate against baseline
        anomalies = await self._toolkit.evaluate_against_baseline(
            agent_id=agent_id,
            tool_name=tool_call.get("tool_name", "unknown"),
            data_volume=tool_call.get("data_volume", 0),
        )

        latency_ms = (time.time() - start) * 1000
        return {
            "agent_id": agent_id,
            "tool_name": tool_call.get("tool_name", "unknown"),
            "action": intercepted.action_taken.value,
            "risk_score": intercepted.risk_score,
            "anomalies": [a.model_dump() for a in anomalies],
            "latency_ms": round(latency_ms, 2),
        }

    async def _persist(self, result: dict[str, Any]) -> None:
        """Persist firewall monitoring results."""
        if self._repository:
            await self._repository.save_firewall_run(result)
