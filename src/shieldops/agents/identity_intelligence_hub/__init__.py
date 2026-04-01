"""Identity Intelligence Hub Agent — cross-IdP identity
correlation and threat detection.

Correlates identity signals across identity providers,
cloud IAM, and agent registries to detect identity-based
threats including privilege escalation, lateral movement,
and compromised non-human identities.
"""

from shieldops.agents.identity_intelligence_hub.graph import (
    create_identity_intelligence_hub_graph,
)

__all__ = ["create_identity_intelligence_hub_graph"]
