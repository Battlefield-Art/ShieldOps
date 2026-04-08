#!/usr/bin/env python3
"""Diff PolicyMiddleware shadow decisions against legacy enforcement.

RFC #243 PR-3 / #262 — observation tooling for the shadow → enforce
rollout. While ``settings.policy_enforce=False``, every non-Allow
decision the middleware makes is logged via structlog as
``policy.middleware.decision``. Meanwhile, the legacy
``rate_limiter`` + ``billing_enforcement`` middleware emit their own
``rate_limit.exceeded`` / ``billing.denied`` events (and still do the
actual blocking). This script consumes both log streams and prints a
summary of divergences so we can confirm the engine's decision
distribution matches legacy before flipping the flag.

Input format (JSONL — one JSON object per line):

    {"event": "policy.middleware.decision",
     "decision": "RateLimited",
     "org_id": "org-a",
     "route_class": "default",
     "path": "/api/v1/agents",
     "enforce": false,
     "ts": 1712500000.0}

    {"event": "rate_limit.exceeded",
     "org_id": "org-a",
     "path": "/api/v1/agents",
     "ts": 1712500000.0}

Requests are matched on ``(org_id, path, ts)`` with a configurable
tolerance window. Any mismatch is reported as either:

- ``shadow_only`` — PolicyMiddleware flagged it, legacy let it through.
  This is usually a *false positive* that needs plan tuning.
- ``legacy_only`` — legacy blocked it, PolicyMiddleware allowed. This
  is a *false negative* — DO NOT flip enforce until these are zero.

Usage::

    python3 scripts/policy_shadow_diff.py \\
        --shadow /var/log/shieldops/policy-shadow.jsonl \\
        --legacy /var/log/shieldops/legacy-enforcement.jsonl \\
        --window 2.0

Simplifying assumption: both logs are structlog JSON renderer output
with ``event`` + ``ts`` fields. If your log shipper uses a different
shape, adapt ``_load_events`` — the diff engine is shape-agnostic.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# --- Events ------------------------------------------------------------


@dataclass(frozen=True)
class DecisionEvent:
    """Normalized form used by the differ — works for both streams."""

    source: str  # "shadow" | "legacy"
    org_id: str
    path: str
    ts: float
    kind: str  # "rate_limited" | "quota_exceeded" | "plan_exceeded"
    raw: dict[str, Any]


_SHADOW_DECISION_TO_KIND = {
    "RateLimited": "rate_limited",
    "QuotaExceeded": "quota_exceeded",
    "PlanExceeded": "plan_exceeded",
}

_LEGACY_EVENT_TO_KIND = {
    "rate_limit.exceeded": "rate_limited",
    "billing.denied": "quota_exceeded",
    "billing.plan_exceeded": "plan_exceeded",
}


def _load_events(path: Path, *, source: str) -> list[DecisionEvent]:
    """Parse a JSONL file into normalized :class:`DecisionEvent` records.

    Unknown events and Allow decisions are silently skipped — this
    script only cares about denial divergences.
    """
    events: list[DecisionEvent] = []
    if not path.exists():
        print(f"warning: {source} log {path} does not exist", file=sys.stderr)
        return events

    with path.open() as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                print(
                    f"warning: {path}:{lineno} is not valid JSON — skipping",
                    file=sys.stderr,
                )
                continue

            name = raw.get("event", "")
            kind: str | None
            if source == "shadow":
                if name != "policy.middleware.decision":
                    continue
                decision = raw.get("decision", "")
                kind = _SHADOW_DECISION_TO_KIND.get(decision)
                if kind is None:
                    continue  # Allow or unknown — skip
            else:
                kind = _LEGACY_EVENT_TO_KIND.get(name)
                if kind is None:
                    continue

            events.append(
                DecisionEvent(
                    source=source,
                    org_id=str(raw.get("org_id", "")),
                    path=str(raw.get("path", "")),
                    ts=float(raw.get("ts", 0.0)),
                    kind=kind,
                    raw=raw,
                )
            )
    return events


# --- Diff engine -------------------------------------------------------


@dataclass
class DiffResult:
    shadow_only: list[DecisionEvent]
    legacy_only: list[DecisionEvent]
    matched: int

    @property
    def divergence_rate(self) -> float:
        total = self.matched + len(self.shadow_only) + len(self.legacy_only)
        if total == 0:
            return 0.0
        return (len(self.shadow_only) + len(self.legacy_only)) / total


def diff(
    shadow: list[DecisionEvent],
    legacy: list[DecisionEvent],
    *,
    window_seconds: float = 2.0,
) -> DiffResult:
    """Match shadow decisions against legacy decisions within a window.

    A match requires identical ``(org_id, path, kind)`` and a timestamp
    delta within ``window_seconds``. Each legacy event is consumed at
    most once. Unmatched entries are reported as divergences.
    """
    legacy_by_key: dict[tuple[str, str, str], list[DecisionEvent]] = {}
    for e in legacy:
        legacy_by_key.setdefault((e.org_id, e.path, e.kind), []).append(e)
    for bucket in legacy_by_key.values():
        bucket.sort(key=lambda e: e.ts)

    shadow_only: list[DecisionEvent] = []
    matched = 0
    consumed: set[int] = set()

    for s in shadow:
        key = (s.org_id, s.path, s.kind)
        bucket = legacy_by_key.get(key, [])
        hit = None
        for candidate in bucket:
            if id(candidate) in consumed:
                continue
            if abs(candidate.ts - s.ts) <= window_seconds:
                hit = candidate
                break
        if hit is None:
            shadow_only.append(s)
        else:
            consumed.add(id(hit))
            matched += 1

    legacy_only = [e for bucket in legacy_by_key.values() for e in bucket if id(e) not in consumed]
    return DiffResult(shadow_only=shadow_only, legacy_only=legacy_only, matched=matched)


# --- CLI ---------------------------------------------------------------


def _print_summary(result: DiffResult) -> None:
    print("=" * 60)
    print("PolicyMiddleware shadow vs legacy divergence report")
    print("=" * 60)
    print(f"Matched decisions:  {result.matched}")
    print(f"Shadow-only (false positive): {len(result.shadow_only)}")
    print(f"Legacy-only (false negative): {len(result.legacy_only)}")
    print(f"Divergence rate:    {result.divergence_rate:.2%}")
    print()

    if result.shadow_only:
        print("Top shadow-only paths (PolicyMiddleware was stricter):")
        counts = Counter((e.path, e.kind) for e in result.shadow_only)
        for (path, kind), n in counts.most_common(10):
            print(f"  {n:>5}  {kind:<16}  {path}")
        print()

    if result.legacy_only:
        print("Top legacy-only paths (PolicyMiddleware MISSED these):")
        counts = Counter((e.path, e.kind) for e in result.legacy_only)
        for (path, kind), n in counts.most_common(10):
            print(f"  {n:>5}  {kind:<16}  {path}")
        print()

    if not result.shadow_only and not result.legacy_only:
        print("No divergences — safe to flip settings.policy_enforce=True.")
    elif result.legacy_only:
        print("BLOCKED: legacy-only denials must be zero before enforcing.")
    else:
        print("Shadow-only divergences present — tune plans, then re-check.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__ or "")
    parser.add_argument(
        "--shadow",
        type=Path,
        required=True,
        help="JSONL log containing policy.middleware.decision events",
    )
    parser.add_argument(
        "--legacy",
        type=Path,
        required=True,
        help="JSONL log containing legacy rate_limit/billing events",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=2.0,
        help="Match window in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--fail-on-legacy-only",
        action="store_true",
        help="Exit 1 if any legacy-only divergences exist",
    )
    args = parser.parse_args(argv)

    shadow_events = _load_events(args.shadow, source="shadow")
    legacy_events = _load_events(args.legacy, source="legacy")
    result = diff(shadow_events, legacy_events, window_seconds=args.window)
    _print_summary(result)

    if args.fail_on_legacy_only and result.legacy_only:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
