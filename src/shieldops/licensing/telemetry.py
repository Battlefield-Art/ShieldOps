"""Anonymous license usage telemetry.

Posts rollup counts to a ShieldOps-hosted license server. Fully opt-out via
``SHIELDOPS_TELEMETRY_OPTOUT=true``. No PII, no customer data — only tier,
anonymized org hash, and aggregate counts.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

DEFAULT_ENDPOINT = "https://license.shieldops.ai/v1/telemetry"
OPTOUT_ENV = "SHIELDOPS_TELEMETRY_OPTOUT"


def is_optout() -> bool:
    return os.getenv(OPTOUT_ENV, "").lower() in {"1", "true", "yes"}


def _hash_org(org_id: str) -> str:
    return hashlib.sha256(org_id.encode("utf-8")).hexdigest()[:16]


class UsageTelemetry:
    """Track anonymous agent execution counts and optionally flush them."""

    def __init__(
        self,
        *,
        org_id: str,
        tier: str,
        endpoint: str | None = None,
    ) -> None:
        self._org_hash = _hash_org(org_id)
        self._tier = tier
        self._endpoint = endpoint or os.getenv("SHIELDOPS_TELEMETRY_ENDPOINT", DEFAULT_ENDPOINT)
        self._agent_executions: int = 0
        self._active_agents: set[str] = set()

    # ------------------------------------------------------------------ #
    # Recording
    # ------------------------------------------------------------------ #
    def record_agent_execution(self, agent_name: str) -> None:
        """Record a single agent execution."""
        if is_optout():
            return
        self._agent_executions += 1
        self._active_agents.add(agent_name)

    def snapshot(self) -> dict[str, Any]:
        return {
            "org_hash": self._org_hash,
            "tier": self._tier,
            "agent_executions": self._agent_executions,
            "unique_agents": len(self._active_agents),
            "timestamp": datetime.now(UTC).isoformat(),
            "version": "1",
        }

    def reset(self) -> None:
        self._agent_executions = 0
        self._active_agents.clear()

    # ------------------------------------------------------------------ #
    # Flush
    # ------------------------------------------------------------------ #
    async def flush(self) -> bool:
        """POST anonymous rollup to the license server.

        Returns ``True`` on success, ``False`` on opt-out or failure. Never
        raises — telemetry MUST NOT break the platform.
        """
        if is_optout():
            logger.debug("license_telemetry_optout")
            return False
        payload = self.snapshot()
        try:
            import httpx

            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(self._endpoint, json=payload)
                resp.raise_for_status()
            self.reset()
            return True
        except Exception as exc:  # noqa: BLE001 — telemetry must never raise
            logger.debug("license_telemetry_flush_failed", error=str(exc))
            return False
