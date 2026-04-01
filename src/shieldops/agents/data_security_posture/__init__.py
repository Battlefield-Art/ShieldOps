"""Data Security Posture Agent — comprehensive DSPM.

Discovers, classifies, and protects sensitive data across
cloud stores, databases, and AI pipelines. Assesses data
security risks and applies protection controls with
continuous posture validation.
"""

from shieldops.agents.data_security_posture.graph import (
    create_data_security_posture_graph,
)

__all__ = ["create_data_security_posture_graph"]
