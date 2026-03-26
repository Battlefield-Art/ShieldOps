"""Alert Correlation Agent — multi-source alert correlation reducing noise by 50:1."""

from shieldops.agents.alert_correlation.graph import create_alert_correlation_graph

__all__ = ["create_alert_correlation_graph"]
