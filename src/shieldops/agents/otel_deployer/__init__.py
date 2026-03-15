"""OTel Deployment Orchestrator Agent — Orchestrates OTel Collector deployments across K8s."""

from .graph import create_otel_deployer_graph

__all__ = ["create_otel_deployer_graph"]
