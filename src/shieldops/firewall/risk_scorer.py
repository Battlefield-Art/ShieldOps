"""Risk scoring engine for AI agent tool calls.

Scores are floats in [0.0, 1.0] where higher = more dangerous.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from fnmatch import fnmatch
from typing import Any

import structlog

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Built-in risk profiles (tool-name glob -> base risk score)
# ---------------------------------------------------------------------------
_BUILTIN_RISK_PROFILES: list[tuple[str, float]] = [
    # Destructive database operations
    ("delete_database", 0.95),
    ("drop_table", 0.95),
    ("truncate_table", 0.95),
    ("format_disk", 0.95),
    ("rm_rf", 0.95),
    # IAM / identity modifications
    ("modify_iam_root", 0.90),
    ("create_iam_admin", 0.90),
    ("delete_iam_*", 0.90),
    ("reset_root_password", 0.90),
    # Network / security group changes
    ("modify_security_group", 0.80),
    ("open_port", 0.80),
    ("disable_firewall", 0.85),
    ("delete_backup", 0.85),
    # Deployment / provisioning
    ("deploy_to_production", 0.70),
    ("create_user", 0.60),
    ("modify_dns", 0.65),
    # Execution
    ("execute_command", 0.75),
    ("run_script", 0.70),
    # Read-only / safe
    ("read_*", 0.10),
    ("list_*", 0.10),
    ("describe_*", 0.10),
    ("get_*", 0.10),
]

# Patterns that hint at PII or credential content in arguments
_SENSITIVE_ARG_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"api_key", re.IGNORECASE),
    re.compile(r"ssn|social.security", re.IGNORECASE),
    re.compile(r"credit.card", re.IGNORECASE),
    re.compile(r"private.key", re.IGNORECASE),
]

_SENSITIVE_VALUE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
    re.compile(r"\b\d{16}\b"),  # credit card (basic)
    re.compile(r"-----BEGIN .* KEY-----"),  # PEM key
]


class RiskScorer:
    """Score tool calls for risk.

    Combines:
      - Tool-name risk profile (built-in + custom overrides)
      - Argument sensitivity (PII / credentials)
      - Caller reputation (configurable per-org)
      - Time-of-day weighting (off-hours = slightly higher)
    """

    def __init__(
        self,
        custom_profiles: dict[str, float] | None = None,
        caller_reputations: dict[str, float] | None = None,
        off_hours_boost: float = 0.05,
    ) -> None:
        # Merge custom on top of built-in (custom wins)
        self._profiles: list[tuple[str, float]] = list(_BUILTIN_RISK_PROFILES)
        if custom_profiles:
            for pattern, score in custom_profiles.items():
                self._profiles.insert(0, (pattern, score))

        self._caller_reputations: dict[str, float] = caller_reputations or {}
        self._off_hours_boost = off_hours_boost

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        caller_identity: str = "",
        timestamp: datetime | None = None,
    ) -> float:
        """Return a risk score in [0.0, 1.0] for the given tool call."""
        base = self._tool_name_score(tool_name)
        arg_bump = self._argument_sensitivity(arguments or {})
        caller_adj = self._caller_adjustment(caller_identity)
        time_adj = self._time_adjustment(timestamp)

        raw = base + arg_bump + caller_adj + time_adj
        score = max(0.0, min(1.0, raw))

        logger.debug(
            "risk_score_computed",
            tool_name=tool_name,
            base=base,
            arg_bump=arg_bump,
            caller_adj=caller_adj,
            time_adj=time_adj,
            final=score,
        )
        return round(score, 4)

    # ------------------------------------------------------------------
    # Internal scoring components
    # ------------------------------------------------------------------

    def _tool_name_score(self, tool_name: str) -> float:
        """Match tool name against risk profiles (first match wins)."""
        for pattern, score in self._profiles:
            if fnmatch(tool_name, pattern):
                return score
        # Unknown tool: moderate baseline
        return 0.40

    def _argument_sensitivity(self, arguments: dict[str, Any]) -> float:
        """Bump risk if arguments contain sensitive keys or values."""
        bump = 0.0
        for key, value in arguments.items():
            for pat in _SENSITIVE_ARG_PATTERNS:
                if pat.search(key):
                    bump += 0.10
                    break
            if isinstance(value, str):
                for pat in _SENSITIVE_VALUE_PATTERNS:
                    if pat.search(value):
                        bump += 0.10
                        break
        return min(bump, 0.30)  # cap argument bump

    def _caller_adjustment(self, caller_identity: str) -> float:
        """Adjust based on caller reputation (negative = trusted, positive = risky)."""
        if not caller_identity:
            return 0.0
        return self._caller_reputations.get(caller_identity, 0.0)

    def _time_adjustment(self, timestamp: datetime | None) -> float:
        """Slight risk boost for off-hours activity (weekends, 22:00-06:00 UTC)."""
        ts = timestamp or datetime.now(UTC)
        hour = ts.hour
        weekday = ts.weekday()
        if weekday >= 5 or hour < 6 or hour >= 22:
            return self._off_hours_boost
        return 0.0
