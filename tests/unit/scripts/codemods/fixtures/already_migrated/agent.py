# RFC #247: agent.py replaces runner.py + graph.py (hand-rolled marker)
"""Pre-existing agent.py with the migration marker."""

from __future__ import annotations


class AlreadyMigratedAgent:
    _shieldops_runtime_migrated = True
    name = "already_migrated"
