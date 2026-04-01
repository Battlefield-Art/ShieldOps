"""Fleet Coordination Engine Agent — multi-agent fleet
operations coordinator.

Coordinates multi-agent fleet operations with load balancing,
health monitoring, task routing, and progress tracking.
Ensures optimal agent utilization and task completion
across the security agent fleet.
"""

from shieldops.agents.fleet_coordination_engine.graph import (
    create_fleet_coordination_engine_graph,
)

__all__ = ["create_fleet_coordination_engine_graph"]
