"""Cross-Cloud Posture Manager — unified posture management across AWS, GCP, Azure."""

from __future__ import annotations

from shieldops.agents.cross_cloud_posture_manager.graph import (
    create_cross_cloud_posture_manager_graph,
)

__all__ = ["create_cross_cloud_posture_manager_graph"]
