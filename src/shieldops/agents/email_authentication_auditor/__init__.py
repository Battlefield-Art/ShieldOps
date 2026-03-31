"""Email Authentication Auditor Agent — DMARC/DKIM/SPF auditing."""

from __future__ import annotations

from shieldops.agents.email_authentication_auditor.graph import (
    create_email_authentication_auditor_graph,
)

__all__ = ["create_email_authentication_auditor_graph"]
