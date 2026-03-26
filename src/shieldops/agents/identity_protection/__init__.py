"""Identity Protection Agent — real-time identity threat detection.

Covers ALL identity providers (Okta, Entra ID, AWS IAM, GCP IAM,
K8s RBAC) plus AI agent identities and MCP client identities.
"""

from shieldops.agents.identity_protection.graph import (
    create_identity_protection_graph,
)

__all__ = ["create_identity_protection_graph"]
