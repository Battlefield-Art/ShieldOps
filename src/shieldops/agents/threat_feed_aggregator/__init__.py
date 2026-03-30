"""Threat Feed Aggregator Agent — aggregate and correlate threat intel."""

from shieldops.agents.threat_feed_aggregator.graph import (
    create_threat_feed_aggregator_graph,
)

__all__ = ["create_threat_feed_aggregator_graph"]
