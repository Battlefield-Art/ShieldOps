"""Adapters for the RequestPolicyEngine ports.

PR-1 ships only the in-memory / test adapters. Production adapters
(``RedisBucketStore``, ``DbPlanLoader``, ``SystemClock``,
``PrometheusMetricsSink``, ``StructlogEventLog``) land in PR-2 once
the core is proven by the contract tests in
``tests/unit/api/policy/test_engine.py``.
"""

from __future__ import annotations

from shieldops.api.policy.adapters.capturing_event_log import CapturingEventLog
from shieldops.api.policy.adapters.in_memory_bucket_store import InMemoryBucketStore
from shieldops.api.policy.adapters.manual_clock import ManualClock
from shieldops.api.policy.adapters.null_metrics import (
    CapturingMetricsSink,
    NullMetricsSink,
)
from shieldops.api.policy.adapters.static_plan_loader import StaticPlanLoader

__all__ = [
    "CapturingEventLog",
    "CapturingMetricsSink",
    "InMemoryBucketStore",
    "ManualClock",
    "NullMetricsSink",
    "StaticPlanLoader",
]
