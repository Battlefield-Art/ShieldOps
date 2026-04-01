"""Intelligence Fusion Center Agent.

Fuses threat intelligence from multiple sources — OSINT,
commercial feeds, internal telemetry, dark web, and ISAC
sharing — into unified threat assessments with correlated
indicators, confidence scoring, and actionable recommendations.
"""

from shieldops.agents.intelligence_fusion_center.graph import (
    create_intelligence_fusion_center_graph,
)

__all__ = ["create_intelligence_fusion_center_graph"]
