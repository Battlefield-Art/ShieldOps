"""Attack Replay Simulator Agent.

Replays known attack techniques in a sandbox to validate
detection and response capabilities.
"""

from shieldops.agents.attack_replay_simulator.graph import (
    create_attack_replay_simulator_graph,
)

__all__ = ["create_attack_replay_simulator_graph"]
