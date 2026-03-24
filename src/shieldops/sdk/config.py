"""ShieldOps SDK configuration — Pydantic model for Agent Firewall SDK settings."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class SDKMode(StrEnum):
    """SDK enforcement mode."""

    AUDIT = "audit"
    ENFORCE = "enforce"


class SDKConfig(BaseModel):
    """Configuration for the ShieldOps Agent Firewall SDK.

    Attributes:
        api_key: ShieldOps API key for authentication.
        endpoint: ShieldOps API base URL.
        mode: Operating mode — ``audit`` logs without blocking, ``enforce`` blocks risky calls.
        agent_id: Optional identifier for the agent being instrumented.
        flush_interval_seconds: How often to flush batched events to the API.
        max_batch_size: Maximum number of events to batch before flushing.
        timeout_seconds: HTTP request timeout for API calls.
        policy_cache_ttl_seconds: How long to cache local policy evaluations.
        verify_ssl: Whether to verify TLS certificates on API calls.
    """

    api_key: str = ""
    endpoint: str = Field(default="https://api.shieldops.io")
    mode: SDKMode = SDKMode.AUDIT
    agent_id: str | None = None
    flush_interval_seconds: int = Field(default=10, ge=1)
    max_batch_size: int = Field(default=100, ge=1)
    timeout_seconds: int = Field(default=5, ge=1)
    policy_cache_ttl_seconds: int = Field(default=300, ge=0)
    verify_ssl: bool = True

    @property
    def is_enforce(self) -> bool:
        return self.mode == SDKMode.ENFORCE

    @property
    def is_audit(self) -> bool:
        return self.mode == SDKMode.AUDIT
