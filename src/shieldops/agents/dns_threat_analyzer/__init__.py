"""DNS Threat Analyzer Agent — detect DNS-based threats."""

from shieldops.agents.dns_threat_analyzer.graph import (
    create_dns_threat_analyzer_graph,
)

__all__ = ["create_dns_threat_analyzer_graph"]
