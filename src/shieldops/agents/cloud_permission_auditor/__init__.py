"""Cloud Permission Auditor Agent — audit cloud IAM for least-privilege violations."""

from shieldops.agents.cloud_permission_auditor.graph import (
    create_cloud_permission_auditor_graph,
)

__all__ = ["create_cloud_permission_auditor_graph"]
