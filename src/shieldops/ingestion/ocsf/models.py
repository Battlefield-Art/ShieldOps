"""OCSF base and category-specific event models.

Implements Open Cybersecurity Schema Framework (OCSF) v1.1 event types
used across the ShieldOps hybrid SIEM for vendor-neutral normalization.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class OCSFBaseEvent(BaseModel):
    """Base OCSF event — all normalized events inherit from this."""

    event_id: UUID = Field(default_factory=uuid4, description="Unique event identifier")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Event timestamp (UTC)",
    )
    event_type: str = Field(
        default="base_event",
        description="OCSF category (e.g. authentication, security_finding)",
    )
    severity: str = Field(default="informational", description="Event severity level")
    source_provider: str = Field(default="unknown", description="Originating vendor/source")
    source_type: str = Field(default="unknown", description="Source event type identifier")
    raw_event: dict[str, Any] = Field(default_factory=dict, description="Original unmodified event")
    normalized: dict[str, Any] = Field(default_factory=dict, description="OCSF-normalized fields")
    enrichments: dict[str, Any] = Field(
        default_factory=dict, description="Agent-added context and enrichments"
    )


class OCSFAuthenticationEvent(OCSFBaseEvent):
    """OCSF Authentication event (category_uid=3001).

    Maps login/logout and identity-related events from CloudTrail ConsoleLogin,
    AssumeRole, SSO providers, etc.
    """

    event_type: str = "authentication"
    user: str = Field(default="", description="Authenticating user or principal")
    src_ip: str = Field(default="", description="Source IP address")
    dst_ip: str = Field(default="", description="Destination IP address")
    action: str = Field(default="login", description="Authentication action (login/logout)")
    status: str = Field(default="unknown", description="Outcome (success/failure)")


class OCSFSecurityFinding(OCSFBaseEvent):
    """OCSF Security Finding event (category_uid=2001).

    Maps detections, alerts, and findings from CrowdStrike, GuardDuty, Wiz, etc.
    """

    event_type: str = "security_finding"
    finding_id: str = Field(default="", description="Vendor-specific finding identifier")
    title: str = Field(default="", description="Finding title or summary")
    confidence: float = Field(default=0.0, ge=0.0, le=100.0, description="Confidence score (0-100)")
    first_seen: datetime | None = Field(default=None, description="First observation time")
    last_seen: datetime | None = Field(default=None, description="Most recent observation time")
    resources: list[dict[str, Any]] = Field(default_factory=list, description="Affected resources")


class OCSFNetworkActivity(OCSFBaseEvent):
    """OCSF Network Activity event (category_uid=4001).

    Maps flow logs, firewall events, and network traffic from VPC Flow Logs,
    NSG logs, packet captures, etc.
    """

    event_type: str = "network_activity"
    src_ip: str = Field(default="", description="Source IP address")
    src_port: int = Field(default=0, ge=0, le=65535, description="Source port")
    dst_ip: str = Field(default="", description="Destination IP address")
    dst_port: int = Field(default=0, ge=0, le=65535, description="Destination port")
    protocol: str = Field(default="", description="Network protocol (tcp/udp/icmp)")
    bytes_in: int = Field(default=0, ge=0, description="Bytes received")
    bytes_out: int = Field(default=0, ge=0, description="Bytes sent")
    action: str = Field(default="allow", description="Firewall action (allow/deny)")


class OCSFAPIActivity(OCSFBaseEvent):
    """OCSF API Activity event (category_uid=6003).

    Maps API calls from CloudTrail, Azure Activity Log, GCP Audit Log, etc.
    """

    event_type: str = "api_activity"
    api_name: str = Field(default="", description="API action or operation name")
    service: str = Field(default="", description="Target service name")
    request_params: dict[str, Any] = Field(
        default_factory=dict, description="API request parameters"
    )
    response_code: int = Field(default=0, description="HTTP or API response code")
    actor: str = Field(default="", description="Identity that invoked the API call")
