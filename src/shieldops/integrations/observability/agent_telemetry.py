"""Agent Telemetry Collector.

Automatically instruments ShieldOps agent runs to emit:
- Log events for each node execution
- Metrics for duration, token usage, and success rate
- Trace spans for the full agent workflow
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from shieldops.integrations.observability.ingest import (
    ObservabilityIngestClient,
)

logger = structlog.get_logger()


class AgentTelemetryCollector:
    """Wraps agent execution to emit structured telemetry."""

    def __init__(self, ingest_client: ObservabilityIngestClient):
        self._client = ingest_client
        self._active_traces: dict[str, dict[str, Any]] = {}

    async def record_agent_start(
        self,
        agent_type: str,
        request_id: str,
        input_data: dict[str, Any],
    ) -> None:
        """Record the start of an agent execution.

        Emits a log event and opens a trace span.
        """
        trace_id = uuid.uuid4().hex
        span_id = uuid.uuid4().hex[:16]
        now_us = int(time.time() * 1_000_000)

        self._active_traces[request_id] = {
            "trace_id": trace_id,
            "root_span_id": span_id,
            "agent_type": agent_type,
            "start_time_us": now_us,
            "node_spans": [],
        }

        # Log event
        await self._client.ingest_logs(
            stream="agent_logs",
            records=[
                {
                    "event": "agent_start",
                    "agent_type": agent_type,
                    "request_id": request_id,
                    "trace_id": trace_id,
                    "span_id": span_id,
                    "level": "info",
                    "input_keys": list(input_data.keys()),
                    "input_size": len(str(input_data)),
                }
            ],
        )

        # Trace span (open)
        await self._client.ingest_traces(
            stream="agent_traces",
            spans=[
                {
                    "trace_id": trace_id,
                    "span_id": span_id,
                    "operation_name": f"{agent_type}.execute",
                    "service_name": "shieldops",
                    "agent_type": agent_type,
                    "start_time_us": now_us,
                    "status": "in_progress",
                    "request_id": request_id,
                }
            ],
        )

        logger.info(
            "agent_telemetry_start",
            agent_type=agent_type,
            request_id=request_id,
            trace_id=trace_id,
        )

    async def record_node_execution(
        self,
        agent_type: str,
        request_id: str,
        node_name: str,
        duration_ms: int,
        status: str,
        output_summary: str,
    ) -> None:
        """Record a single node execution within an agent run."""
        trace_info = self._active_traces.get(request_id, {})
        trace_id = trace_info.get("trace_id", "")
        parent_span_id = trace_info.get("root_span_id", "")
        span_id = uuid.uuid4().hex[:16]
        now_us = int(time.time() * 1_000_000)

        # Log event
        await self._client.ingest_logs(
            stream="agent_logs",
            records=[
                {
                    "event": "node_execution",
                    "agent_type": agent_type,
                    "request_id": request_id,
                    "node_name": node_name,
                    "duration_ms": duration_ms,
                    "status": status,
                    "output_summary": output_summary[:500],
                    "trace_id": trace_id,
                    "span_id": span_id,
                    "level": "info" if status == "success" else "warn",
                }
            ],
        )

        # Metric
        await self._client.ingest_metrics(
            stream="agent_metrics",
            records=[
                {
                    "metric_name": "node_execution_duration_ms",
                    "agent_type": agent_type,
                    "node_name": node_name,
                    "value": duration_ms,
                    "status": status,
                },
                {
                    "metric_name": "node_execution_count",
                    "agent_type": agent_type,
                    "node_name": node_name,
                    "value": 1,
                    "status": status,
                },
            ],
        )

        # Trace span
        span = {
            "trace_id": trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "operation_name": f"{agent_type}.{node_name}",
            "service_name": "shieldops",
            "agent_type": agent_type,
            "start_time_us": now_us - (duration_ms * 1000),
            "end_time_us": now_us,
            "duration_ms": duration_ms,
            "status": status,
        }
        await self._client.ingest_traces(stream="agent_traces", spans=[span])

        if request_id in self._active_traces:
            self._active_traces[request_id]["node_spans"].append(span)

    async def record_agent_complete(
        self,
        agent_type: str,
        request_id: str,
        status: str,
        duration_ms: int,
        reasoning_steps: int,
        confidence: float,
    ) -> None:
        """Record the completion of an agent execution."""
        trace_info = self._active_traces.pop(request_id, {})
        trace_id = trace_info.get("trace_id", "")
        root_span_id = trace_info.get("root_span_id", "")
        start_us = trace_info.get("start_time_us", 0)
        now_us = int(time.time() * 1_000_000)

        # Log event
        await self._client.ingest_logs(
            stream="agent_logs",
            records=[
                {
                    "event": "agent_complete",
                    "agent_type": agent_type,
                    "request_id": request_id,
                    "status": status,
                    "duration_ms": duration_ms,
                    "reasoning_steps": reasoning_steps,
                    "confidence": confidence,
                    "trace_id": trace_id,
                    "level": "info" if status == "success" else "error",
                }
            ],
        )

        # Metrics
        await self._client.ingest_metrics(
            stream="agent_metrics",
            records=[
                {
                    "metric_name": "agent_execution_duration_ms",
                    "agent_type": agent_type,
                    "value": duration_ms,
                    "status": status,
                },
                {
                    "metric_name": "agent_execution_count",
                    "agent_type": agent_type,
                    "value": 1,
                    "status": status,
                },
                {
                    "metric_name": "agent_confidence",
                    "agent_type": agent_type,
                    "value": confidence,
                },
                {
                    "metric_name": "agent_reasoning_steps",
                    "agent_type": agent_type,
                    "value": reasoning_steps,
                },
            ],
        )

        # Close root trace span
        await self._client.ingest_traces(
            stream="agent_traces",
            spans=[
                {
                    "trace_id": trace_id,
                    "span_id": root_span_id,
                    "operation_name": f"{agent_type}.execute",
                    "service_name": "shieldops",
                    "agent_type": agent_type,
                    "start_time_us": start_us,
                    "end_time_us": now_us,
                    "duration_ms": duration_ms,
                    "status": status,
                    "reasoning_steps": reasoning_steps,
                    "confidence": confidence,
                    "request_id": request_id,
                }
            ],
        )

        logger.info(
            "agent_telemetry_complete",
            agent_type=agent_type,
            request_id=request_id,
            status=status,
            duration_ms=duration_ms,
        )

    async def record_llm_call(
        self,
        agent_type: str,
        node_name: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        latency_ms: int,
    ) -> None:
        """Record an LLM API call with token usage and latency."""
        # Log
        await self._client.ingest_logs(
            stream="llm_logs",
            records=[
                {
                    "event": "llm_call",
                    "agent_type": agent_type,
                    "node_name": node_name,
                    "model": model,
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": input_tokens + output_tokens,
                    "latency_ms": latency_ms,
                    "level": "info",
                }
            ],
        )

        # Metrics
        await self._client.ingest_metrics(
            stream="llm_metrics",
            records=[
                {
                    "metric_name": "llm_input_tokens",
                    "agent_type": agent_type,
                    "model": model,
                    "value": input_tokens,
                },
                {
                    "metric_name": "llm_output_tokens",
                    "agent_type": agent_type,
                    "model": model,
                    "value": output_tokens,
                },
                {
                    "metric_name": "llm_latency_ms",
                    "agent_type": agent_type,
                    "model": model,
                    "value": latency_ms,
                },
                {
                    "metric_name": "llm_call_count",
                    "agent_type": agent_type,
                    "model": model,
                    "value": 1,
                },
            ],
        )

        logger.debug(
            "llm_telemetry",
            agent_type=agent_type,
            model=model,
            tokens=input_tokens + output_tokens,
            latency_ms=latency_ms,
        )
