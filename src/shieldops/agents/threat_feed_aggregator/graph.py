"""Threat Feed Aggregator Agent — LangGraph StateGraph."""

from __future__ import annotations

from typing import Any

from langgraph.graph import StateGraph

from shieldops.agents.framework import build_linear_graph

from .models import ThreatFeedAggregatorState
from .nodes import (
    collect_feeds,
    correlate_threats,
    distribute_intel,
    enrich_context,
    generate_report,
    normalize_iocs,
)
from .tools import ThreatFeedAggregatorToolkit


def build_graph(toolkit: ThreatFeedAggregatorToolkit):  # type: ignore[no-untyped-def]
    """Build the threat_feed_aggregator agent graph (linear sequence)."""
    return build_linear_graph(
        ThreatFeedAggregatorState,
        [
            ("collect_feeds", collect_feeds),
            ("normalize_iocs", normalize_iocs),
            ("correlate_threats", correlate_threats),
            ("enrich_context", enrich_context),
            ("distribute_intel", distribute_intel),
            ("report", generate_report),
        ],
        toolkit=toolkit,
    )


def create_threat_feed_aggregator_graph(
    misp_client: Any | None = None,
    taxii_client: Any | None = None,
    otx_client: Any | None = None,
    vt_client: Any | None = None,
) -> StateGraph:  # type: ignore[type-arg]
    """Create the Threat Feed Aggregator graph."""
    toolkit = ThreatFeedAggregatorToolkit(
        misp_client=misp_client,
        taxii_client=taxii_client,
        otx_client=otx_client,
        vt_client=vt_client,
    )
    return build_graph(toolkit)
