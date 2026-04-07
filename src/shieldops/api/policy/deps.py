"""PolicyDeps — one frozen dataclass groups the 5 ports into one handle.

Borrowed from the minimal-interface design (Design A of RFC #243) so
``app.py`` wires one thing and tests construct one thing to override:

    engine = RequestPolicyEngine(PolicyDeps(
        buckets=RedisBucketStore(redis_client),
        plans=SettingsPlanLoader(settings),
        clock=SystemClock(),
        metrics=PrometheusMetricsSink(registry),
        events=StructlogEventLog(logger),
    ))

    # Tests
    deps = PolicyDeps(
        buckets=InMemoryBucketStore(),
        plans=StaticPlanLoader({"org-a": Plan(tier="free", rps=5, burst=5)}),
        clock=ManualClock(start=0.0),
        metrics=NullMetrics(),
        events=CapturingEventLog(),
    )
    engine = RequestPolicyEngine(deps)
"""

from __future__ import annotations

from dataclasses import dataclass

from shieldops.api.policy.ports import (
    BucketStore,
    Clock,
    EventLog,
    MetricsSink,
    PlanLoader,
)
from shieldops.api.policy.types import OverrideTable


@dataclass(frozen=True)
class PolicyDeps:
    """Composition root for the policy engine.

    All cross-boundary dependencies flow through this frozen dataclass.
    Adding a new dependency is a deliberate schema change, not a silent
    subsystem import.
    """

    buckets: BucketStore
    plans: PlanLoader
    clock: Clock
    metrics: MetricsSink
    events: EventLog
    overrides: OverrideTable | None = None
