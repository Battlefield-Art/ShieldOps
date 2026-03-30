"""Observability Pipeline Optimizer Agent — optimize OTel, Datadog, Splunk pipelines."""

from shieldops.agents.observability_pipeline_optimizer.graph import (
    create_observability_pipeline_optimizer_graph,
)

__all__ = ["create_observability_pipeline_optimizer_graph"]
