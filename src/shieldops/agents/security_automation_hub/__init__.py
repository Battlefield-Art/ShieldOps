"""Security Automation Hub Agent.

Central hub for security automation workflows -- orchestrates
playbooks, runbooks, and automated responses across the
security operations pipeline.
"""

from shieldops.agents.security_automation_hub.graph import (
    create_security_automation_hub_graph,
)

__all__ = ["create_security_automation_hub_graph"]
