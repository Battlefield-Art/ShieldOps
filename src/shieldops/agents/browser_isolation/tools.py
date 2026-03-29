"""Browser Isolation Agent — Tool functions."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import structlog

from .models import IsolationAction, SessionRisk

logger = structlog.get_logger()

_HIGH_RISK_DOMAINS = {
    "*.ru",
    "*.cn",
    "*.tk",
    "*.top",
    "pastebin.com",
    "transfer.sh",
}

_BREAKOUT_TECHNIQUES = [
    "dom_clobbering",
    "plugin_exploit",
    "clipboard_exfil",
    "webrtc_leak",
    "dns_rebinding",
    "iframe_escape",
]


def _generate_id(prefix: str, *parts: str) -> str:
    raw = f"{':'.join(parts)}:{datetime.now(UTC).isoformat()}"
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:8].upper()}"


class BrowserIsolationToolkit:
    """Tools for browser isolation management."""

    def __init__(
        self,
        isolation_client: Any | None = None,
        proxy_client: Any | None = None,
    ) -> None:
        self._isolation = isolation_client
        self._proxy = proxy_client

    async def collect_sessions(self, tenant_id: str) -> list[dict[str, Any]]:
        """Collect active browser sessions."""
        logger.info("bi.collect_sessions", tenant_id=tenant_id)
        if self._isolation:
            try:
                return await self._isolation.list_sessions(tenant_id=tenant_id)
            except Exception:
                logger.exception("bi.collect_sessions.error")
        return [
            {
                "session_id": "SES-001",
                "user": "alice@corp.com",
                "url": "https://docs.google.com/spreadsheets",
                "domain": "docs.google.com",
                "isolated": True,
                "bytes_transferred": 45000,
            },
            {
                "session_id": "SES-002",
                "user": "bob@corp.com",
                "url": "https://suspicious-site.tk/download",
                "domain": "suspicious-site.tk",
                "isolated": True,
                "bytes_transferred": 250000,
            },
            {
                "session_id": "SES-003",
                "user": "charlie@corp.com",
                "url": "https://pastebin.com/raw/abc123",
                "domain": "pastebin.com",
                "isolated": True,
                "bytes_transferred": 12000,
            },
            {
                "session_id": "SES-004",
                "user": "diana@corp.com",
                "url": "https://internal-wiki.corp.com",
                "domain": "internal-wiki.corp.com",
                "isolated": False,
                "bytes_transferred": 8000,
            },
        ]

    async def detect_breakouts(
        self, sessions: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int]:
        """Detect sandbox breakout attempts."""
        logger.info("bi.detect_breakouts", session_count=len(sessions))
        attempts: list[dict[str, Any]] = []
        blocked = 0
        now = datetime.now(UTC)

        for sess in sessions:
            domain = sess.get("domain", "")
            transferred = sess.get("bytes_transferred", 0)

            if (
                any(domain.endswith(d.lstrip("*")) for d in _HIGH_RISK_DOMAINS if d.startswith("*"))
                or domain in _HIGH_RISK_DOMAINS
            ):
                attempts.append(
                    {
                        "id": _generate_id("BRK", sess["session_id"]),
                        "session_id": sess["session_id"],
                        "technique": "high_risk_domain",
                        "severity": SessionRisk.HIGH.value,
                        "blocked": True,
                        "details": f"Session to high-risk domain: {domain}",
                        "detected_at": now.isoformat(),
                    }
                )
                blocked += 1

            if transferred > 200000:
                attempts.append(
                    {
                        "id": _generate_id("BRK", sess["session_id"], "exfil"),
                        "session_id": sess["session_id"],
                        "technique": "data_exfiltration",
                        "severity": SessionRisk.CRITICAL.value,
                        "blocked": True,
                        "details": (f"Large data transfer: {transferred} bytes via {domain}"),
                        "detected_at": now.isoformat(),
                    }
                )
                blocked += 1

        return attempts, blocked

    async def evaluate_policies(
        self, sessions: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], int]:
        """Evaluate sessions against isolation policies."""
        logger.info("bi.evaluate_policies")
        violations: list[dict[str, Any]] = []
        enforced = 0

        for sess in sessions:
            if not sess.get("isolated", False):
                violations.append(
                    {
                        "session_id": sess["session_id"],
                        "domain": sess.get("domain", ""),
                        "violation": "not_isolated",
                        "action": IsolationAction.ISOLATE.value,
                    }
                )
                enforced += 1

        return violations, enforced

    async def sandbox_content(self, sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Sandbox suspicious content."""
        logger.info("bi.sandbox")
        sandboxed: list[dict[str, Any]] = []
        for sess in sessions:
            domain = sess.get("domain", "")
            if (
                any(domain.endswith(d.lstrip("*")) for d in _HIGH_RISK_DOMAINS if d.startswith("*"))
                or domain in _HIGH_RISK_DOMAINS
            ):
                sandboxed.append(
                    {
                        "session_id": sess["session_id"],
                        "domain": domain,
                        "action": IsolationAction.SANDBOX.value,
                        "content_type": "web_page",
                    }
                )
        return sandboxed
