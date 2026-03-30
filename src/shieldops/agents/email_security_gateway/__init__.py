"""Email Security Gateway Agent — email threat analysis and phishing detection."""

from __future__ import annotations

from shieldops.agents.email_security_gateway.graph import (
    create_email_security_gateway_graph,
)

__all__ = ["create_email_security_gateway_graph"]
