"""Attack Narrative Builder Agent — builds human-readable attack narratives
from correlated security events with MITRE ATT&CK and kill chain mapping."""

from shieldops.agents.attack_narrative_builder.graph import (
    create_attack_narrative_builder_graph,
)

__all__ = ["create_attack_narrative_builder_graph"]
