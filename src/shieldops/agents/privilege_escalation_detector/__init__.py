"""Privilege Escalation Detector Agent — detect sudo abuse, role changes, IAM modifications."""

from .graph import create_privilege_escalation_detector_graph

__all__ = ["create_privilege_escalation_detector_graph"]
