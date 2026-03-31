"""Secret Sprawl Detector Agent — credential sprawl detection."""

from __future__ import annotations

from shieldops.agents.secret_sprawl_detector.graph import (
    create_secret_sprawl_detector_graph,
)

__all__ = ["create_secret_sprawl_detector_graph"]
