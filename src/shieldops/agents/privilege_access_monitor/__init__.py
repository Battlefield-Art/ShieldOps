"""Privilege Access Monitor Agent — PAM and JIT access enforcement."""

from __future__ import annotations

from shieldops.agents.privilege_access_monitor.graph import (
    create_privilege_access_monitor_graph,
)

__all__ = ["create_privilege_access_monitor_graph"]
