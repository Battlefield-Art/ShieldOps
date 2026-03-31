"""Security Automation Pipeline Agent -- CI/CD security gate integration."""

from __future__ import annotations

from shieldops.agents.security_automation_pipeline.graph import (
    create_security_automation_pipeline_graph,
)

__all__ = ["create_security_automation_pipeline_graph"]
