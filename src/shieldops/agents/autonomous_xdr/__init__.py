"""Autonomous XDR Agent — vendor-neutral Extended Detection
and Response across endpoint, network, cloud, and identity.

Correlates signals from CrowdStrike Falcon, Microsoft
Defender, SentinelOne, Carbon Black, Wiz, Prisma Cloud,
Okta, and Entra ID — not locked to any single vendor.
"""

from shieldops.agents.autonomous_xdr.graph import (
    build_graph,
    create_autonomous_xdr_graph,
)

__all__ = [
    "build_graph",
    "create_autonomous_xdr_graph",
]
