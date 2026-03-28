"""Auto Ticket Manager Agent — auto-creates and tracks JIRA/ServiceNow tickets."""

from shieldops.agents.auto_ticket_manager.graph import (
    create_auto_ticket_manager_graph,
)

__all__ = ["create_auto_ticket_manager_graph"]
