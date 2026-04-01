"""Multi-Tenant Isolation Guard — validates tenant boundaries."""

from __future__ import annotations

from shieldops.agents.multi_tenant_isolation_guard.graph import (
    create_multi_tenant_isolation_guard_graph,
)

__all__ = ["create_multi_tenant_isolation_guard_graph"]
