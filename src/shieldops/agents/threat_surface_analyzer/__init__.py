"""Threat Surface Analyzer Agent.

Continuously analyzes and maps the organization's threat surface
across cloud, on-prem, and SaaS environments — discovering assets,
mapping exposures, assessing risks, and recommending mitigations.
"""

from shieldops.agents.threat_surface_analyzer.graph import (
    create_threat_surface_analyzer_graph,
)

__all__ = ["create_threat_surface_analyzer_graph"]
