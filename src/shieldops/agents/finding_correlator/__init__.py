"""Finding Correlator Agent — deduplicates and correlates findings across scanners."""

from shieldops.agents.finding_correlator.graph import (
    create_finding_correlator_graph,
)

__all__ = ["create_finding_correlator_graph"]
