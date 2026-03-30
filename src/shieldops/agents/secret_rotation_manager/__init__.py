"""Secret Rotation Manager Agent — zero-downtime credential rotation."""

from shieldops.agents.secret_rotation_manager.graph import (
    create_secret_rotation_manager_graph,
)

__all__ = ["create_secret_rotation_manager_graph"]
