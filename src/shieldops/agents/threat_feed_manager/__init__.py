"""Threat Feed Manager Agent — aggregate, normalize, and score threat intel feeds."""

from shieldops.agents.threat_feed_manager.graph import (
    create_threat_feed_manager_graph,
)

__all__ = ["create_threat_feed_manager_graph"]
