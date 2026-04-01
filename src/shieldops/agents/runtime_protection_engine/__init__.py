"""Runtime Protection Engine Agent.

Real-time protection engine for AI agent runtime, detecting
and blocking anomalous behaviors through telemetry collection,
behavior analysis, anomaly detection, and policy enforcement.
"""

from shieldops.agents.runtime_protection_engine.graph import (
    create_runtime_protection_engine_graph,
)

__all__ = ["create_runtime_protection_engine_graph"]
