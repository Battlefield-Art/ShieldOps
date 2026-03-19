"""Pre-built Observability Dashboard Definitions.

Generates dashboard JSON compatible with OpenObserve's dashboard API.
Dashboards cover agent activity, LLM costs, and incident timelines.
"""

from __future__ import annotations

import uuid
from typing import Any


def _panel(
    title: str,
    query: str,
    panel_type: str = "bar",
    stream: str = "agent_metrics",
    position: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Create a single dashboard panel definition."""
    return {
        "id": uuid.uuid4().hex[:12],
        "type": panel_type,
        "title": title,
        "config": {
            "queries": [
                {
                    "query": query,
                    "stream": stream,
                    "stream_type": "logs",
                    "customQuery": True,
                }
            ],
            "show_legends": True,
        },
        "layout": position or {"x": 0, "y": 0, "w": 6, "h": 4, "i": "0"},
    }


def agent_overview_dashboard() -> dict[str, Any]:
    """Dashboard showing all agent activity: invocations, latency, success rate."""
    return {
        "title": "ShieldOps Agent Overview",
        "description": "Real-time view of all agent invocations, latency, and success rates.",
        "role": "admin",
        "owner": "shieldops",
        "created": "",
        "panels": [
            _panel(
                title="Agent Invocations (Last 1h)",
                query=(
                    "SELECT agent_type, count(*) as invocations "
                    "FROM agent_logs "
                    "WHERE event = 'agent_complete' "
                    "GROUP BY agent_type ORDER BY invocations DESC"
                ),
                panel_type="bar",
                stream="agent_logs",
                position={"x": 0, "y": 0, "w": 6, "h": 4, "i": "1"},
            ),
            _panel(
                title="Agent Success Rate (%)",
                query=(
                    "SELECT agent_type, "
                    "round(sum(CASE WHEN status='success' THEN 1 ELSE 0 END) * 100.0 "
                    "/ count(*), 2) as success_rate "
                    "FROM agent_logs WHERE event = 'agent_complete' "
                    "GROUP BY agent_type"
                ),
                panel_type="table",
                stream="agent_logs",
                position={"x": 6, "y": 0, "w": 6, "h": 4, "i": "2"},
            ),
            _panel(
                title="Agent P50 / P95 Latency (ms)",
                query=(
                    "SELECT agent_type, "
                    "approx_percentile_cont(duration_ms, 0.5) as p50, "
                    "approx_percentile_cont(duration_ms, 0.95) as p95 "
                    "FROM agent_logs WHERE event = 'agent_complete' "
                    "GROUP BY agent_type"
                ),
                panel_type="bar",
                stream="agent_logs",
                position={"x": 0, "y": 4, "w": 6, "h": 4, "i": "3"},
            ),
            _panel(
                title="Active Agent Traces",
                query=(
                    "SELECT trace_id, agent_type, status, duration_ms "
                    "FROM agent_traces "
                    "WHERE status = 'in_progress' "
                    "ORDER BY _timestamp DESC LIMIT 20"
                ),
                panel_type="table",
                stream="agent_traces",
                position={"x": 6, "y": 4, "w": 6, "h": 4, "i": "4"},
            ),
            _panel(
                title="Node Execution Heatmap",
                query=(
                    "SELECT agent_type, node_name, "
                    "avg(duration_ms) as avg_duration "
                    "FROM agent_logs WHERE event = 'node_execution' "
                    "GROUP BY agent_type, node_name"
                ),
                panel_type="heatmap",
                stream="agent_logs",
                position={"x": 0, "y": 8, "w": 12, "h": 4, "i": "5"},
            ),
            _panel(
                title="Agent Confidence Distribution",
                query=(
                    "SELECT agent_type, avg(confidence) as avg_conf, "
                    "min(confidence) as min_conf, max(confidence) as max_conf "
                    "FROM agent_logs WHERE event = 'agent_complete' "
                    "GROUP BY agent_type"
                ),
                panel_type="bar",
                stream="agent_logs",
                position={"x": 0, "y": 12, "w": 12, "h": 4, "i": "6"},
            ),
        ],
        "variables": [],
        "version": 1,
    }


def llm_cost_dashboard() -> dict[str, Any]:
    """Dashboard showing LLM token usage and cost by agent and model."""
    return {
        "title": "LLM Cost & Token Usage",
        "description": "Track LLM API costs, token consumption, and latency across agents.",
        "role": "admin",
        "owner": "shieldops",
        "created": "",
        "panels": [
            _panel(
                title="Total Tokens by Model (Last 1h)",
                query=(
                    "SELECT model, "
                    "sum(input_tokens) as total_input, "
                    "sum(output_tokens) as total_output "
                    "FROM llm_logs GROUP BY model"
                ),
                panel_type="bar",
                stream="llm_logs",
                position={"x": 0, "y": 0, "w": 6, "h": 4, "i": "1"},
            ),
            _panel(
                title="Token Usage by Agent",
                query=(
                    "SELECT agent_type, "
                    "sum(input_tokens + output_tokens) as total_tokens "
                    "FROM llm_logs GROUP BY agent_type "
                    "ORDER BY total_tokens DESC"
                ),
                panel_type="bar",
                stream="llm_logs",
                position={"x": 6, "y": 0, "w": 6, "h": 4, "i": "2"},
            ),
            _panel(
                title="LLM Latency P50/P95 by Model",
                query=(
                    "SELECT model, "
                    "approx_percentile_cont(latency_ms, 0.5) as p50, "
                    "approx_percentile_cont(latency_ms, 0.95) as p95 "
                    "FROM llm_logs GROUP BY model"
                ),
                panel_type="line",
                stream="llm_logs",
                position={"x": 0, "y": 4, "w": 6, "h": 4, "i": "3"},
            ),
            _panel(
                title="LLM Calls Over Time",
                query=(
                    "SELECT histogram(_timestamp) as time_bucket, "
                    "count(*) as calls "
                    "FROM llm_logs GROUP BY time_bucket"
                ),
                panel_type="line",
                stream="llm_logs",
                position={"x": 6, "y": 4, "w": 6, "h": 4, "i": "4"},
            ),
            _panel(
                title="Estimated Cost by Agent (USD)",
                query=(
                    "SELECT agent_type, model, "
                    "round(sum(input_tokens) * 0.000003 + "
                    "sum(output_tokens) * 0.000015, 4) as est_cost_usd "
                    "FROM llm_logs GROUP BY agent_type, model "
                    "ORDER BY est_cost_usd DESC"
                ),
                panel_type="table",
                stream="llm_logs",
                position={"x": 0, "y": 8, "w": 12, "h": 4, "i": "5"},
            ),
        ],
        "variables": [],
        "version": 1,
    }


def incident_timeline_dashboard() -> dict[str, Any]:
    """Dashboard showing incident detection -> investigation -> remediation timeline."""
    return {
        "title": "Incident Response Timeline",
        "description": (
            "End-to-end incident lifecycle: detection, investigation, remediation, and resolution."
        ),
        "role": "admin",
        "owner": "shieldops",
        "created": "",
        "panels": [
            _panel(
                title="Incidents by Status",
                query=(
                    "SELECT status, count(*) as total "
                    "FROM agent_logs "
                    "WHERE agent_type IN ('investigation', 'incident_commander', "
                    "'incident_response') AND event = 'agent_complete' "
                    "GROUP BY status"
                ),
                panel_type="pie",
                stream="agent_logs",
                position={"x": 0, "y": 0, "w": 4, "h": 4, "i": "1"},
            ),
            _panel(
                title="Mean Time to Detect (MTTD)",
                query=(
                    "SELECT avg(duration_ms) / 1000 as mttd_seconds "
                    "FROM agent_logs "
                    "WHERE agent_type = 'investigation' AND event = 'agent_complete'"
                ),
                panel_type="metric",
                stream="agent_logs",
                position={"x": 4, "y": 0, "w": 4, "h": 4, "i": "2"},
            ),
            _panel(
                title="Mean Time to Remediate (MTTR)",
                query=(
                    "SELECT avg(duration_ms) / 1000 as mttr_seconds "
                    "FROM agent_logs "
                    "WHERE agent_type IN ('remediation', 'auto_remediation') "
                    "AND event = 'agent_complete'"
                ),
                panel_type="metric",
                stream="agent_logs",
                position={"x": 8, "y": 0, "w": 4, "h": 4, "i": "3"},
            ),
            _panel(
                title="Incident Timeline (Recent 24h)",
                query=(
                    "SELECT _timestamp, agent_type, event, status, duration_ms "
                    "FROM agent_logs "
                    "WHERE agent_type IN ('investigation', 'incident_commander', "
                    "'remediation', 'auto_remediation', 'incident_response') "
                    "ORDER BY _timestamp DESC LIMIT 100"
                ),
                panel_type="table",
                stream="agent_logs",
                position={"x": 0, "y": 4, "w": 12, "h": 6, "i": "4"},
            ),
            _panel(
                title="Remediation Confidence Distribution",
                query=(
                    "SELECT confidence, count(*) as count "
                    "FROM agent_logs "
                    "WHERE agent_type IN ('remediation', 'auto_remediation') "
                    "AND event = 'agent_complete' "
                    "GROUP BY confidence"
                ),
                panel_type="histogram",
                stream="agent_logs",
                position={"x": 0, "y": 10, "w": 12, "h": 4, "i": "5"},
            ),
        ],
        "variables": [],
        "version": 1,
    }
