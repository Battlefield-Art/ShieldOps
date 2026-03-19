"""Pre-built Honeycomb Query Definitions.

Honeycomb queries use HEATMAP, COUNT, P95, GROUP BY for analysis.
These definitions can be used to create saved queries via the Honeycomb
API or to drive dashboard widgets in the ShieldOps UI.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HoneycombQuery(BaseModel):
    """A Honeycomb query definition."""

    name: str
    dataset: str = "shieldops"
    calculations: list[dict[str, str]] = Field(default_factory=list)
    filters: list[dict[str, Any]] = Field(default_factory=list)
    breakdowns: list[str] = Field(default_factory=list)
    time_range: int = 3600  # seconds


class HoneycombQueryManager:
    """Factory for pre-built Honeycomb queries tailored to ShieldOps agents."""

    def agent_latency_heatmap(self) -> HoneycombQuery:
        """Heatmap of agent execution duration grouped by agent type."""
        return HoneycombQuery(
            name="Agent Latency Heatmap",
            calculations=[
                {"op": "HEATMAP", "column": "duration_ms"},
                {"op": "P95", "column": "duration_ms"},
            ],
            filters=[
                {"column": "type", "op": "=", "value": "agent_event"},
            ],
            breakdowns=["agent.type"],
            time_range=3600,
        )

    def agent_error_rate_by_type(self) -> HoneycombQuery:
        """Error rate per agent type over the last hour."""
        return HoneycombQuery(
            name="Agent Error Rate by Type",
            calculations=[
                {"op": "COUNT"},
                {"op": "COUNT_DISTINCT", "column": "trace.trace_id"},
            ],
            filters=[
                {"column": "type", "op": "=", "value": "agent_event"},
                {"column": "agent.status", "op": "!=", "value": "ok"},
            ],
            breakdowns=["agent.type", "agent.status"],
            time_range=3600,
        )

    def llm_token_usage_breakdown(self) -> HoneycombQuery:
        """LLM token consumption breakdown by agent and node."""
        return HoneycombQuery(
            name="LLM Token Usage Breakdown",
            calculations=[
                {"op": "SUM", "column": "agent.llm_tokens"},
                {"op": "AVG", "column": "agent.llm_tokens"},
                {"op": "MAX", "column": "agent.llm_tokens"},
            ],
            filters=[
                {"column": "agent.llm_tokens", "op": ">", "value": "0"},
            ],
            breakdowns=["agent.type", "agent.node_name"],
            time_range=3600,
        )

    def trace_duration_by_node(self) -> HoneycombQuery:
        """Trace span duration distribution grouped by node name."""
        return HoneycombQuery(
            name="Trace Duration by Node",
            calculations=[
                {"op": "HEATMAP", "column": "duration_ms"},
                {"op": "P50", "column": "duration_ms"},
                {"op": "P99", "column": "duration_ms"},
            ],
            filters=[
                {"column": "trace.trace_id", "op": "exists"},
            ],
            breakdowns=["name"],
            time_range=3600,
        )

    def confidence_distribution(self) -> HoneycombQuery:
        """Distribution of agent confidence scores by type."""
        return HoneycombQuery(
            name="Agent Confidence Distribution",
            calculations=[
                {"op": "HEATMAP", "column": "agent.confidence"},
                {"op": "AVG", "column": "agent.confidence"},
            ],
            filters=[
                {"column": "agent.confidence", "op": ">", "value": "0"},
            ],
            breakdowns=["agent.type"],
            time_range=7200,
        )

    def get_all_queries(self) -> list[HoneycombQuery]:
        """Return all pre-built queries."""
        return [
            self.agent_latency_heatmap(),
            self.agent_error_rate_by_type(),
            self.llm_token_usage_breakdown(),
            self.trace_duration_by_node(),
            self.confidence_distribution(),
        ]
