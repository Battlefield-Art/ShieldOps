"""SOC Metrics Analyzer Agent — analyzes SOC performance and recommends optimizations."""

from __future__ import annotations

from shieldops.agents.soc_metrics_analyzer.graph import (
    create_soc_metrics_analyzer_graph,
)

__all__ = ["create_soc_metrics_analyzer_graph"]
