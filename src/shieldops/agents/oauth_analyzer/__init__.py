"""OAuth Grant Analyzer Agent — discovers and risk-scores OAuth grants across SaaS and cloud."""

from shieldops.agents.oauth_analyzer.graph import create_oauth_analyzer_graph

__all__ = ["create_oauth_analyzer_graph"]
