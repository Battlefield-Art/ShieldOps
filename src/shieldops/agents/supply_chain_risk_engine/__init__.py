"""Supply Chain Risk Engine Agent.

Continuously assesses software supply chain risk across
dependencies, containers, and third-party integrations.
"""

from shieldops.agents.supply_chain_risk_engine.graph import (
    create_supply_chain_risk_engine_graph,
)

__all__ = ["create_supply_chain_risk_engine_graph"]
