"""Exposure Management Agent — unified attack surface management.

Discovers and prioritizes exposures across cloud, identity,
AI, and code surfaces. Covers AI-specific attack surfaces
(exposed MCP servers, unprotected AI endpoints, RAG data
exposure) that legacy vendors do not address.
"""

from shieldops.agents.exposure_management.graph import (
    create_exposure_management_graph,
)

__all__ = ["create_exposure_management_graph"]
