"""Cloud Secret Vault Agent — manages cloud secrets and key lifecycle."""

from __future__ import annotations

from shieldops.agents.cloud_secret_vault.graph import (
    create_cloud_secret_vault_graph,
)

__all__ = ["create_cloud_secret_vault_graph"]
