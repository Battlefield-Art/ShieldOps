"""OTel Logs Pipeline Agent — Log receiver, processor, and exporter management."""

from .graph import create_otel_logs_pipeline_graph

__all__ = ["create_otel_logs_pipeline_graph"]
