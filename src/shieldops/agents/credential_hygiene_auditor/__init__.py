"""Credential Hygiene Auditor Agent.

Audits credential hygiene across the organization -- password
age, rotation compliance, secret sprawl, and risk scoring.
"""

from shieldops.agents.credential_hygiene_auditor.graph import (
    create_credential_hygiene_auditor_graph,
)

__all__ = ["create_credential_hygiene_auditor_graph"]
