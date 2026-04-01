"""Unified Risk Dashboard Agent.

Aggregates risk signals from all security agents into a
unified risk scoring and reporting dashboard with posture
assessment and action prioritization.
"""

from shieldops.agents.unified_risk_dashboard.graph import (
    create_unified_risk_dashboard_graph,
)

__all__ = ["create_unified_risk_dashboard_graph"]
