"""Behavioral Threat Detector Agent.

Detects threats through behavioral analysis of users,
entities, and network traffic patterns using baseline
comparison and deviation scoring.
"""

from shieldops.agents.behavioral_threat_detector.graph import (
    create_behavioral_threat_detector_graph,
)

__all__ = ["create_behavioral_threat_detector_graph"]
