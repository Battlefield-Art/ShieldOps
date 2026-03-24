"""Kafka topic definitions for AI Security events."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum

from pydantic import BaseModel, Field


class SecurityTopic(StrEnum):
    """Kafka topics for AI Security event streams."""

    FIREWALL_EVENTS = "shieldops.firewall.events"
    FIREWALL_ANOMALIES = "shieldops.firewall.anomalies"
    FIREWALL_CIRCUIT_BREAKER = "shieldops.firewall.circuit-breaker"
    NHI_CHANGES = "shieldops.nhi.changes"
    NHI_SHADOW_AI = "shieldops.nhi.shadow-ai"
    MCP_ALERTS = "shieldops.mcp.alerts"
    MCP_GOD_KEYS = "shieldops.mcp.god-keys"
    SOC_SITUATIONS = "shieldops.soc.situations"
    SOC_ACTIONS = "shieldops.soc.actions"
    SECURITY_WEBHOOKS = "shieldops.security.webhooks"


class SecurityEvent(BaseModel):
    """Canonical event envelope for AI Security Kafka messages.

    Every security event published through the event streaming system is
    wrapped in this model to ensure a consistent schema across all topics.
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    topic: SecurityTopic = SecurityTopic.FIREWALL_EVENTS
    event_type: str = ""
    agent_id: str = ""
    severity: str = "info"
    payload: dict = Field(default_factory=dict)  # type: ignore[type-arg]
    timestamp: float = Field(default_factory=time.time)


# ── Topic configurations ────────────────────────────────────────────────────
# Defines partition counts, retention, and cleanup policy for each topic.

TOPIC_CONFIGS: dict[str, dict] = {  # type: ignore[type-arg]
    SecurityTopic.FIREWALL_EVENTS: {
        "partitions": 12,
        "retention_ms": 86_400_000,  # 1 day
        "cleanup_policy": "delete",
    },
    SecurityTopic.FIREWALL_ANOMALIES: {
        "partitions": 6,
        "retention_ms": 604_800_000,  # 7 days
        "cleanup_policy": "delete",
    },
    SecurityTopic.FIREWALL_CIRCUIT_BREAKER: {
        "partitions": 3,
        "retention_ms": 604_800_000,  # 7 days
        "cleanup_policy": "compact",
    },
    SecurityTopic.NHI_CHANGES: {
        "partitions": 6,
        "retention_ms": 2_592_000_000,  # 30 days
        "cleanup_policy": "compact",
    },
    SecurityTopic.NHI_SHADOW_AI: {
        "partitions": 6,
        "retention_ms": 2_592_000_000,  # 30 days
        "cleanup_policy": "delete",
    },
    SecurityTopic.MCP_ALERTS: {
        "partitions": 6,
        "retention_ms": 604_800_000,  # 7 days
        "cleanup_policy": "delete",
    },
    SecurityTopic.MCP_GOD_KEYS: {
        "partitions": 3,
        "retention_ms": 2_592_000_000,  # 30 days
        "cleanup_policy": "compact",
    },
    SecurityTopic.SOC_SITUATIONS: {
        "partitions": 6,
        "retention_ms": 2_592_000_000,  # 30 days
        "cleanup_policy": "compact",
    },
    SecurityTopic.SOC_ACTIONS: {
        "partitions": 6,
        "retention_ms": 2_592_000_000,  # 30 days
        "cleanup_policy": "delete",
    },
    SecurityTopic.SECURITY_WEBHOOKS: {
        "partitions": 6,
        "retention_ms": 604_800_000,  # 7 days
        "cleanup_policy": "delete",
    },
}


ALL_SECURITY_TOPICS: list[str] = [t.value for t in SecurityTopic]
