"""ShieldOps Interceptor — core interception middleware for the Agent Firewall SDK."""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from typing import Any

import httpx
import structlog
from pydantic import BaseModel, Field

from shieldops.sdk.config import SDKConfig

logger = structlog.get_logger()

_MAX_RETRIES = 3
_BACKOFF_BASE = 0.5  # seconds — exponential: 0.5, 1.0, 2.0


class ShieldOpsDeniedError(Exception):
    """Raised when a tool call is denied in enforce mode."""

    def __init__(self, tool_name: str, risk_score: float, reasons: list[str]) -> None:
        self.tool_name = tool_name
        self.risk_score = risk_score
        self.reasons = reasons
        super().__init__(f"Tool '{tool_name}' denied (risk={risk_score}): {'; '.join(reasons)}")


class InterceptResult(BaseModel):
    """Result of an interception evaluation."""

    decision: str = "allow"  # allow | block
    risk_score: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evaluated_at: float = Field(default_factory=time.time)


class AuditEvent(BaseModel):
    """A single auditable event recorded by the interceptor."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    tool_name: str = ""
    args_hash: str = ""
    result_summary: str = ""
    decision: str = "allow"
    risk_score: float = 0.0
    latency_ms: float = 0.0
    timestamp: float = Field(default_factory=time.time)


# --- Blocked-tool rules (local policy cache) ---

_DEFAULT_BLOCKED_PATTERNS: set[str] = {
    "delete_database",
    "drop_table",
    "modify_iam_root",
    "rm_rf",
    "format_disk",
    "disable_firewall",
    "delete_backup",
}

_HIGH_RISK_PATTERNS: set[str] = {
    "execute_command",
    "run_shell",
    "modify_security_group",
    "change_iam_policy",
    "create_user",
    "rotate_credentials",
}


class ShieldOpsInterceptor:
    """Core interception middleware for the ShieldOps Agent Firewall SDK.

    Evaluates tool calls against ShieldOps policies (local cache or remote API),
    records audit events, and batches them for export.
    """

    def __init__(self, config: SDKConfig) -> None:
        self._config = config
        self._events: list[AuditEvent] = []
        self._batch: list[AuditEvent] = []
        self._blocked_tools: set[str] = set(_DEFAULT_BLOCKED_PATTERNS)
        self._high_risk_tools: set[str] = set(_HIGH_RISK_PATTERNS)
        self._call_count: int = 0
        self._block_count: int = 0
        logger.info(
            "shieldops_interceptor.initialized",
            mode=config.mode.value,
            endpoint=config.endpoint,
            agent_id=config.agent_id,
        )

    # -- interception ---------------------------------------------------------

    def intercept(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        agent_id: str | None = None,
    ) -> InterceptResult:
        """Evaluate a tool call against ShieldOps policy.

        Returns an InterceptResult with decision (allow/block), risk_score, and reasons.
        In ``audit`` mode, risky calls are logged but never blocked.
        In ``enforce`` mode, blocked-pattern calls return decision=block.
        """
        self._call_count += 1
        effective_agent = agent_id or self._config.agent_id or "unknown"
        reasons: list[str] = []
        risk_score = 0.0
        decision = "allow"

        normalized = tool_name.lower().strip()

        # Check blocked patterns
        if normalized in self._blocked_tools:
            risk_score = 1.0
            reasons.append(f"Tool '{tool_name}' matches blocked pattern")
            if self._config.is_enforce:
                decision = "block"
                self._block_count += 1

        # Check high-risk patterns
        elif normalized in self._high_risk_tools:
            risk_score = 0.7
            reasons.append(f"Tool '{tool_name}' is high-risk — requires review")

        # Basic arg heuristics
        if args:
            args_str = str(args).lower()
            if "production" in args_str or "prod" in args_str:
                risk_score = min(risk_score + 0.2, 1.0)
                reasons.append("Arguments reference production environment")
            if "wildcard" in args_str or "*" in args_str:
                risk_score = min(risk_score + 0.1, 1.0)
                reasons.append("Arguments contain wildcard patterns")

        if not reasons:
            reasons.append("No policy violations detected")

        result = InterceptResult(
            decision=decision,
            risk_score=round(risk_score, 3),
            reasons=reasons,
        )

        logger.info(
            "shieldops_interceptor.intercept",
            tool_name=tool_name,
            agent_id=effective_agent,
            decision=decision,
            risk_score=result.risk_score,
        )
        return result

    # -- convenience check -----------------------------------------------------

    def check(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        agent_id: str | None = None,
    ) -> InterceptResult:
        """Evaluate a tool call and raise on deny in enforce mode.

        In **audit** mode, logs the evaluation but always returns the result
        without raising.  In **enforce** mode, raises ``ShieldOpsDeniedError``
        when the decision is ``block``.
        """
        result = self.intercept(tool_name, args, agent_id)
        if result.decision == "block" and self._config.is_enforce:
            raise ShieldOpsDeniedError(
                tool_name=tool_name,
                risk_score=result.risk_score,
                reasons=result.reasons,
            )
        return result

    # -- audit recording ------------------------------------------------------

    def record(
        self,
        tool_name: str,
        args_hash: str = "",
        result_summary: str = "",
        latency_ms: float = 0.0,
        decision: str = "allow",
        risk_score: float = 0.0,
    ) -> AuditEvent:
        """Record a tool execution event to the audit log."""
        event = AuditEvent(
            agent_id=self._config.agent_id or "unknown",
            tool_name=tool_name,
            args_hash=args_hash,
            result_summary=result_summary[:500],
            decision=decision,
            risk_score=risk_score,
            latency_ms=latency_ms,
        )
        self._events.append(event)
        self._batch.append(event)
        if len(self._batch) >= self._config.max_batch_size:
            self.flush()
        return event

    def flush(self) -> int:
        """Send batched events to the ShieldOps API.

        Attempts async HTTP POST to the backend. Falls back to clearing the
        local buffer if the event loop is not running or the API is unreachable.
        Returns the number of events flushed.
        """
        count = len(self._batch)
        if count == 0:
            return 0

        events_to_send = list(self._batch)
        self._batch.clear()

        # Attempt async send — fall back gracefully if no running loop
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._send_batch(events_to_send))
        except RuntimeError:
            # No running event loop — try synchronous send
            try:
                asyncio.run(self._send_batch(events_to_send))
            except Exception as exc:
                logger.warning(
                    "shieldops_interceptor.flush_fallback",
                    event_count=count,
                    error=str(exc),
                )
        logger.info(
            "shieldops_interceptor.flush",
            event_count=count,
            endpoint=self._config.endpoint,
        )
        return count

    async def _send_batch(self, events: list[AuditEvent]) -> None:
        """POST batched audit events to the ShieldOps backend with retry."""
        url = f"{self._config.endpoint}/api/v1/agent-firewall/events"
        payload = {
            "agent_id": self._config.agent_id or "unknown",
            "events": [e.model_dump() for e in events],
            "sent_at": time.time(),
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._config.api_key}",
            "X-ShieldOps-Agent-Id": self._config.agent_id or "unknown",
        }

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                async with httpx.AsyncClient(
                    timeout=self._config.timeout_seconds,
                    verify=self._config.verify_ssl,
                ) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                    resp.raise_for_status()
                    logger.info(
                        "shieldops_interceptor.batch_sent",
                        event_count=len(events),
                        status=resp.status_code,
                        attempt=attempt + 1,
                    )
                    return
            except (httpx.HTTPStatusError, httpx.RequestError, httpx.TimeoutException) as exc:
                last_exc = exc
                wait = _BACKOFF_BASE * (2**attempt)
                logger.warning(
                    "shieldops_interceptor.send_retry",
                    attempt=attempt + 1,
                    max_retries=_MAX_RETRIES,
                    wait_seconds=wait,
                    error=str(exc),
                )
                await asyncio.sleep(wait)

        # All retries exhausted — log but don't crash
        logger.error(
            "shieldops_interceptor.send_failed",
            event_count=len(events),
            error=str(last_exc),
        )

    # -- reporting ------------------------------------------------------------

    def get_audit_report(self) -> dict[str, Any]:
        """Summarize all intercepted calls."""
        tool_freq: dict[str, int] = {}
        decision_freq: dict[str, int] = {}
        total_latency = 0.0
        for e in self._events:
            tool_freq[e.tool_name] = tool_freq.get(e.tool_name, 0) + 1
            decision_freq[e.decision] = decision_freq.get(e.decision, 0) + 1
            total_latency += e.latency_ms
        return {
            "total_events": len(self._events),
            "total_intercepts": self._call_count,
            "total_blocks": self._block_count,
            "by_tool": tool_freq,
            "by_decision": decision_freq,
            "avg_latency_ms": round(total_latency / len(self._events), 2) if self._events else 0.0,
            "mode": self._config.mode.value,
            "agent_id": self._config.agent_id,
        }

    # -- context manager ------------------------------------------------------

    async def __aenter__(self) -> ShieldOpsInterceptor:
        logger.info("shieldops_interceptor.session_start", agent_id=self._config.agent_id)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.flush()
        logger.info(
            "shieldops_interceptor.session_end",
            total_events=len(self._events),
            total_blocks=self._block_count,
        )

    # -- utilities ------------------------------------------------------------

    @staticmethod
    def hash_args(args: dict[str, Any]) -> str:
        """Create a deterministic hash of tool arguments for audit logging."""
        raw = str(sorted(args.items())).encode()
        return hashlib.sha256(raw).hexdigest()[:16]
