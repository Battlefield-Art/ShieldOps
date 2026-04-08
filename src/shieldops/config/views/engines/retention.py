"""Read-only view over retention/TTL engines fields.

Decomposed from the 1,820-LOC sub/engines.py monolith (RFC #241 PR-6 / #254).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from shieldops.config.sub.engines import EnginesConfig

_FIELDS: frozenset[str] = frozenset(
    {
        "idempotency_ttl_seconds",
        "cache_l1_ttl_seconds",
        "correlation_trace_ttl_minutes",
        "batch_job_ttl_hours",
        "timeline_retention_days",
        "runbook_execution_ttl_days",
        "drift_retention_days",
        "rate_limit_analytics_retention_hours",
        "sli_pipeline_data_retention_hours",
        "log_retention_optimizer_default_retention_days",
        "retention_policy_max_retention_days",
        "knowledge_mesh_ttl_seconds",
        "prompt_cache_ttl_seconds",
    }
)


class EnginesRetentionView:
    """Read-only projection over engines fields in this category."""

    __slots__ = ("_engines",)

    def __init__(self, engines: EnginesConfig) -> None:
        self._engines = engines

    def __getattr__(self, name: str) -> Any:
        if name in _FIELDS:
            return getattr(self._engines, name)
        raise AttributeError(f"EnginesRetentionView has no attribute {name!r}")

    @classmethod
    def field_names(cls) -> frozenset[str]:
        return _FIELDS
