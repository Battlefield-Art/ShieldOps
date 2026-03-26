"""Autonomous SOC Agent — AI-native Security Operations Center.

Open, composable autonomous SOC that works with existing SIEM
investments (Splunk, Elastic, Sentinel). No rip-and-replace.
"""

from shieldops.agents.autonomous_soc.graph import (
    create_autonomous_soc_graph,
)

__all__ = ["create_autonomous_soc_graph"]
