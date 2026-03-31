"""SIEM Rule Optimizer Agent — detection rule optimization and tuning."""

from __future__ import annotations

from shieldops.agents.siem_rule_optimizer.graph import (
    create_siem_rule_optimizer_graph,
)

__all__ = ["create_siem_rule_optimizer_graph"]
