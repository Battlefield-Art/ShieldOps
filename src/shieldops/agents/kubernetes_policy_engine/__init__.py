"""Kubernetes Policy Engine Agent — admission control and policy enforcement."""

from __future__ import annotations

from shieldops.agents.kubernetes_policy_engine.graph import (
    create_kubernetes_policy_engine_graph,
)

__all__ = ["create_kubernetes_policy_engine_graph"]
