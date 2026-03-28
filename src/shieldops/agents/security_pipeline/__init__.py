"""Security Pipeline Agent — master orchestrator chaining discovery to verification."""

from shieldops.agents.security_pipeline.graph import (
    create_security_pipeline_graph,
)

__all__ = ["create_security_pipeline_graph"]
