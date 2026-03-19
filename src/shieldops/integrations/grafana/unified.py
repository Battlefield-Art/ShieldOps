"""Unified Grafana LGTM Client.

Single entry point for sending all telemetry (logs, metrics, traces)
to the Grafana stack (Loki + Mimir + Tempo).  Correlates signals by
injecting trace IDs into logs and metrics labels.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from shieldops.integrations.grafana.loki import LokiClient
from shieldops.integrations.grafana.mimir import MimirClient
from shieldops.integrations.grafana.tempo import TempoClient

logger = structlog.get_logger()


class GrafanaLGTMClient:
    """Unified client for the full Grafana LGTM stack.

    Wraps :class:`LokiClient`, :class:`MimirClient`, and :class:`TempoClient`
    behind a single interface.  The :meth:`record_agent_execution` method
    pushes a correlated log + metric + span in one call.
    """

    def __init__(
        self,
        loki_url: str = "http://localhost:3100",
        mimir_url: str = "http://localhost:9009",
        tempo_url: str = "http://localhost:3200",
        tenant_id: str = "shieldops",
        username: str = "",
        password: str = "",
    ):
        self.loki = LokiClient(
            url=loki_url,
            tenant_id=tenant_id,
            username=username,
            password=password,
        )
        self.mimir = MimirClient(
            url=mimir_url,
            tenant_id=tenant_id,
            username=username,
            password=password,
        )
        self.tempo = TempoClient(
            url=tempo_url,
            tenant_id=tenant_id,
            username=username,
            password=password,
        )
        self._tenant_id = tenant_id

    async def record_agent_execution(
        self,
        agent_type: str,
        request_id: str,
        node_name: str,
        duration_ms: float,
        status: str,
        log_message: str,
        trace_id: str = "",
        span_id: str = "",
    ) -> dict[str, Any]:
        """Record a complete agent execution event across all three signals.

        Pushes:
        - **Log** to Loki with agent context and trace correlation
        - **Metric** (duration + invocation count) to Mimir
        - **Span** to Tempo with duration and status

        Returns a summary dict with the results from each backend.
        """
        if not trace_id:
            trace_id = uuid.uuid4().hex
        if not span_id:
            span_id = uuid.uuid4().hex[:16]

        level = "info" if status == "success" else "error"

        # --- Loki: structured log ---
        log_result = await self.loki.push_agent_log(
            agent_type=agent_type,
            level=level,
            message=log_message,
            extra_labels={"node": node_name},
            structured_metadata={
                "request_id": request_id,
                "trace_id": trace_id,
                "span_id": span_id,
                "status": status,
                "duration_ms": str(duration_ms),
            },
        )

        # --- Mimir: duration metric ---
        metric_result = await self.mimir.push_agent_metric(
            agent_type=agent_type,
            metric_name="execution_duration_ms",
            value=duration_ms,
            extra_labels={
                "node": node_name,
                "status": status,
                "request_id": request_id,
            },
        )

        # --- Tempo: trace span ---
        span_result = await self.tempo.push_agent_span(
            agent_type=agent_type,
            node_name=node_name,
            trace_id=trace_id,
            span_id=span_id,
            duration_us=int(duration_ms * 1000),
        )

        logger.info(
            "grafana_lgtm_recorded",
            agent_type=agent_type,
            node=node_name,
            trace_id=trace_id,
            duration_ms=duration_ms,
        )

        return {
            "trace_id": trace_id,
            "span_id": span_id,
            "loki": log_result,
            "mimir": metric_result,
            "tempo": span_result,
        }

    async def query_agent_logs(
        self,
        agent_type: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Query recent logs for a specific agent type via LogQL."""
        logql = f'{{platform="shieldops", agent_type="{agent_type}"}} | json'
        return await self.loki.query(logql, limit=limit)

    async def query_agent_metrics(
        self,
        agent_type: str,
        metric_name: str = "execution_duration_ms",
        step: str = "30s",
    ) -> list[dict[str, Any]]:
        """Query agent metrics via PromQL."""
        promql = f'shieldops_agent_{metric_name}{{agent_type="{agent_type}"}}'
        return await self.mimir.query(promql, step=step)
