"""Threat Intelligence Platform Agent.

Multi-source threat intelligence aggregation with digital risk
protection — counters CrowdStrike Counter Adversary Operations
by combining OSINT, commercial feeds, dark web monitoring, and
internal telemetry with LLM-driven correlation.
"""

from shieldops.agents.threat_intelligence_platform.graph import (
    create_threat_intelligence_platform_graph,
)

__all__ = ["create_threat_intelligence_platform_graph"]
