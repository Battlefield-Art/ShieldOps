"""Cross-Vendor Correlator Agent — correlates alerts across security vendors."""

from shieldops.agents.cross_vendor_correlator.graph import (
    create_cross_vendor_correlator_graph,
)

__all__ = ["create_cross_vendor_correlator_graph"]
