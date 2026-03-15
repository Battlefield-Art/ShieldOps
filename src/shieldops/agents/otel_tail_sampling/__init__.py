"""OTel Tail Sampling Agent — Tail-based sampling policy management for OpenTelemetry."""

from .graph import create_otel_tail_sampling_graph

__all__ = ["create_otel_tail_sampling_graph"]
