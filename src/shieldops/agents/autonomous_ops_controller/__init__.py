"""Autonomous Ops Controller Agent.

Controls and coordinates autonomous operations across the
security agent fleet -- assessing fleet health, planning
operations, dispatching tasks, monitoring execution, and
evaluating outcomes.
"""

from shieldops.agents.autonomous_ops_controller.graph import (
    create_autonomous_ops_controller_graph,
)

__all__ = ["create_autonomous_ops_controller_graph"]
