"""In-memory adapters for all 9 AgentRuntime ports.

Each adapter is deliberately small — the goal is for the full
lifecycle contract test to be readable in one screen. Production
adapters land in PR-2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class AllowAllPolicy:
    """Policy port that allows everything. Default for contract tests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def evaluate(self, action: str, context: dict[str, Any]) -> bool:
        self.calls.append((action, context))
        return True


class DenyPolicy:
    """Policy port that denies a named action."""

    def __init__(self, *, deny_action: str) -> None:
        self._deny_action = deny_action
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def evaluate(self, action: str, context: dict[str, Any]) -> bool:
        self.calls.append((action, context))
        return action != self._deny_action


# ---------------------------------------------------------------------------
# License
# ---------------------------------------------------------------------------


@dataclass
class InMemoryLicenseManager:
    """License manager that consults a pre-seeded allow/deny dict."""

    allowed_features: set[str] = field(default_factory=set)
    deny_all: bool = False
    calls: list[tuple[str, str]] = field(default_factory=list)

    def check(self, agent_name: str, tenant_id: str) -> bool:
        self.calls.append((agent_name, tenant_id))
        if self.deny_all:
            return False
        # If no allowed_features seeded, default = allow all.
        if not self.allowed_features:
            return True
        return agent_name in self.allowed_features


# ---------------------------------------------------------------------------
# Persistence + Audit
# ---------------------------------------------------------------------------


@dataclass
class InMemoryPersistence:
    """Captures every save_state call."""

    states: dict[str, dict[str, Any]] = field(default_factory=dict)
    history: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    async def save_state(self, run_id: str, state: dict[str, Any]) -> None:
        self.states[run_id] = dict(state)
        self.history.append((run_id, dict(state)))


@dataclass
class CapturingAuditLog:
    """Captures every audit.log call as a dict for assertions."""

    entries: list[dict[str, Any]] = field(default_factory=list)

    async def log(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        metadata: dict[str, Any],
    ) -> None:
        self.entries.append(
            {
                "actor": actor,
                "action": action,
                "target": target,
                "metadata": dict(metadata),
            }
        )


# ---------------------------------------------------------------------------
# WebSocket hub
# ---------------------------------------------------------------------------


@dataclass
class CapturingHub:
    """Captures every publish call. Tests assert on the topic + payload."""

    published: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    async def publish(self, channel: str, event: dict[str, Any]) -> None:
        self.published.append((channel, dict(event)))


# ---------------------------------------------------------------------------
# Evolution recorder
# ---------------------------------------------------------------------------


@dataclass
class InMemoryEvolutionRecorder:
    """Captures every record_run call."""

    runs: list[dict[str, Any]] = field(default_factory=list)

    async def record_run(
        self,
        *,
        agent_name: str,
        tenant_id: str,
        success: bool,
        latency_ms: float,
        node_count: int,
    ) -> None:
        self.runs.append(
            {
                "agent_name": agent_name,
                "tenant_id": tenant_id,
                "success": success,
                "latency_ms": latency_ms,
                "node_count": node_count,
            }
        )


# ---------------------------------------------------------------------------
# Connector router
# ---------------------------------------------------------------------------


class InMemoryConnectorRouter:
    """Null connector router — returns empty dicts. Tests that need
    specific responses use :class:`ScriptedConnectorRouter`."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def call(self, vendor: str, operation: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((vendor, operation, dict(kwargs)))
        return {}


class ScriptedConnectorRouter:
    """Returns pre-seeded responses keyed by (vendor, operation)."""

    def __init__(
        self,
        responses: dict[tuple[str, str], dict[str, Any]],
    ) -> None:
        self._responses = dict(responses)
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def call(self, vendor: str, operation: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append((vendor, operation, dict(kwargs)))
        return self._responses.get((vendor, operation), {})


# ---------------------------------------------------------------------------
# Clock + Logger
# ---------------------------------------------------------------------------


@dataclass
class ManualClock:
    """Controllable clock with ``monotonic_ms`` for latency math."""

    start_ts: float = 1_700_000_000.0
    start_monotonic: float = 0.0
    _advanced: float = 0.0

    def now(self) -> float:
        return self.start_ts + self._advanced

    def monotonic_ms(self) -> float:
        return (self.start_monotonic + self._advanced) * 1000.0

    def advance(self, seconds: float) -> None:
        self._advanced += float(seconds)


class NullAgentLogger:
    """Discards all log calls. Tests use a Capturing variant if needed."""

    def __init__(self) -> None:
        self._bound: dict[str, Any] = {}

    def bind(self, **kw: Any) -> NullAgentLogger:
        new = NullAgentLogger()
        new._bound = {**self._bound, **kw}
        return new

    def info(self, msg: str, **kw: Any) -> None:  # noqa: D401
        pass

    def warning(self, msg: str, **kw: Any) -> None:  # noqa: D401
        pass

    def error(self, msg: str, **kw: Any) -> None:  # noqa: D401
        pass
