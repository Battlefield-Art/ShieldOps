"""Session Hijack Detector Agent — detect token theft, cookie manipulation, and session replay."""

from shieldops.agents.session_hijack_detector.graph import (
    create_session_hijack_detector_graph,
)

__all__ = ["create_session_hijack_detector_graph"]
