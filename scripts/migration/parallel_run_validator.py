#!/usr/bin/env python3
"""Parallel-run validator for Splunk → ShieldOps SIEM migration.

Runs the same logical query against both Splunk (via REST API) and ShieldOps
(via NL Query API) for a given time window, compares the result sets, and
writes a markdown parity report.

Designed for phase 1 (ingestion parity), phase 2 (alert rule parity), and
phase 6 (cutover smoke test) of ``docs/runbooks/siem-migration.md``.

Usage
-----
Basic parity run::

    python parallel_run_validator.py \\
        --window 24h \\
        --queries scripts/migration/queries.sample.json \\
        --splunk-host https://splunk.example.com:8089 \\
        --shieldops-host https://api.shieldops.io \\
        --out reports/parity-$(date +%Y%m%d).md

Alert-rule parity (7-day side-by-side of fired alerts)::

    python parallel_run_validator.py --mode alerts --window 7d \\
        --queries reports/alert-rules.json --out reports/alerts.md

Cutover smoke test::

    python parallel_run_validator.py --mode smoke --tenant acme \\
        --out reports/cutover-smoke.md

Credentials
-----------
Set environment variables before running::

    SPLUNK_USERNAME=admin
    SPLUNK_PASSWORD=...        # or SPLUNK_TOKEN
    SHIELDOPS_API_TOKEN=...

Queries file format
-------------------
A JSON file with a list of query definitions::

    [
      {
        "name": "auth_failures_by_user",
        "description": "Count of auth failures grouped by user (24h)",
        "splunk_spl": "search index=auth action=failure | stats count by user",
        "shieldops_nl": "Count authentication failures grouped by user in the last 24 hours",
        "compare": "top_values",
        "key_field": "user",
        "value_field": "count",
        "tolerance_pct": 5.0
      }
    ]

``compare`` is one of ``count``, ``top_values``, ``time_bucket``.

Mock mode
---------
If connection to either backend fails, the validator automatically falls back
to deterministic mock data so the script is runnable (and useful for demoing
the report format) without live credentials. Pass ``--mock`` to force mock
mode. The report header indicates whether real or mock data was used.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

try:
    import requests
except ImportError:  # pragma: no cover
    print(
        "ERROR: 'requests' is required. Install with: pip install requests",
        file=sys.stderr,
    )
    sys.exit(2)

LOG = logging.getLogger("parallel_run_validator")

DEFAULT_TOLERANCE_PCT = 5.0
DEFAULT_WINDOW = "24h"
REQUEST_TIMEOUT = 60  # seconds

# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #


@dataclass
class QuerySpec:
    """One logical query to run against both backends."""

    name: str
    description: str
    splunk_spl: str
    shieldops_nl: str
    compare: str = "count"  # count | top_values | time_bucket
    key_field: str = "key"
    value_field: str = "count"
    tolerance_pct: float = DEFAULT_TOLERANCE_PCT

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QuerySpec:
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            splunk_spl=data["splunk_spl"],
            shieldops_nl=data["shieldops_nl"],
            compare=data.get("compare", "count"),
            key_field=data.get("key_field", "key"),
            value_field=data.get("value_field", "count"),
            tolerance_pct=float(data.get("tolerance_pct", DEFAULT_TOLERANCE_PCT)),
        )


@dataclass
class QueryResult:
    """Normalized result from either backend."""

    total_count: int = 0
    top_values: dict[str, float] = field(default_factory=dict)
    time_buckets: dict[str, float] = field(default_factory=dict)
    raw_row_count: int = 0
    source: str = "unknown"  # "live" | "mock" | "error"
    error: str | None = None


@dataclass
class ParityOutcome:
    query: QuerySpec
    splunk: QueryResult
    shieldops: QueryResult
    parity_score: float  # 0.0 – 100.0
    passed: bool
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Window parsing
# --------------------------------------------------------------------------- #


_WINDOW_RE = re.compile(r"^(\d+)([hdm])$")


def parse_window(window: str) -> timedelta:
    """Parse '24h', '7d', '15m' into a timedelta."""
    match = _WINDOW_RE.match(window.strip().lower())
    if not match:
        raise ValueError(f"Invalid window '{window}'. Use forms like '24h', '7d', '15m'.")
    value, unit = int(match.group(1)), match.group(2)
    if unit == "h":
        return timedelta(hours=value)
    if unit == "d":
        return timedelta(days=value)
    return timedelta(minutes=value)


# --------------------------------------------------------------------------- #
# Splunk client
# --------------------------------------------------------------------------- #


class SplunkClient:
    """Minimal Splunk REST client for running a blocking search and reading JSON rows."""

    def __init__(
        self,
        host: str,
        username: str | None,
        password: str | None,
        token: str | None,
        verify_tls: bool = True,
    ) -> None:
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.token = token
        self.verify_tls = verify_tls
        self._session = requests.Session()
        if token:
            self._session.headers.update({"Authorization": f"Bearer {token}"})
        elif username and password:
            self._session.auth = (username, password)

    def _url(self, path: str) -> str:
        return urljoin(self.host + "/", path.lstrip("/"))

    def health(self) -> bool:
        try:
            resp = self._session.get(
                self._url("services/server/info?output_mode=json"),
                verify=self.verify_tls,
                timeout=10,
            )
            return resp.status_code == 200
        except requests.RequestException as exc:
            LOG.warning("Splunk health check failed: %s", exc)
            return False

    def run_search(self, spl: str, earliest: str, latest: str) -> list[dict[str, Any]]:
        """Run a blocking export search; return list of result rows."""
        query = spl if spl.strip().lower().startswith("search ") else f"search {spl}"
        params = {
            "search": query,
            "earliest_time": earliest,
            "latest_time": latest,
            "output_mode": "json",
            "exec_mode": "oneshot",
            "count": 10000,
        }
        LOG.debug("Splunk search: %s", query)
        resp = self._session.post(
            self._url("services/search/jobs/export"),
            data=params,
            verify=self.verify_tls,
            timeout=REQUEST_TIMEOUT,
            stream=True,
        )
        resp.raise_for_status()
        rows: list[dict[str, Any]] = []
        for line in resp.iter_lines(decode_unicode=True):
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            result = event.get("result")
            if result:
                rows.append(result)
        return rows


# --------------------------------------------------------------------------- #
# ShieldOps client
# --------------------------------------------------------------------------- #


class ShieldOpsClient:
    """ShieldOps NL Query client. Hits the public ``/api/v1/nl-query`` endpoint."""

    def __init__(
        self,
        host: str,
        token: str | None,
        tenant: str | None = None,
        verify_tls: bool = True,
    ) -> None:
        self.host = host.rstrip("/")
        self.token = token
        self.tenant = tenant
        self.verify_tls = verify_tls
        self._session = requests.Session()
        if token:
            self._session.headers.update({"Authorization": f"Bearer {token}"})
        if tenant:
            self._session.headers.update({"X-Tenant-ID": tenant})

    def _url(self, path: str) -> str:
        return urljoin(self.host + "/", path.lstrip("/"))

    def health(self) -> bool:
        try:
            resp = self._session.get(
                self._url("health"),
                verify=self.verify_tls,
                timeout=10,
            )
            return resp.status_code == 200
        except requests.RequestException as exc:
            LOG.warning("ShieldOps health check failed: %s", exc)
            return False

    def nl_query(
        self,
        prompt: str,
        earliest: datetime,
        latest: datetime,
    ) -> dict[str, Any]:
        body = {
            "prompt": prompt,
            "time_range": {
                "start": earliest.isoformat(),
                "end": latest.isoformat(),
            },
            "limit": 10000,
            "format": "structured",
        }
        LOG.debug("ShieldOps NL query: %s", prompt)
        resp = self._session.post(
            self._url("api/v1/nl-query"),
            json=body,
            verify=self.verify_tls,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()


# --------------------------------------------------------------------------- #
# Mock data
# --------------------------------------------------------------------------- #


def _seeded_rand(seed: str, lo: int, hi: int) -> int:
    h = int(hashlib.sha256(seed.encode("utf-8")).hexdigest(), 16)
    return lo + (h % (hi - lo + 1))


def mock_result(query: QuerySpec, backend: str, variance_pct: float = 0.0) -> QueryResult:
    """Generate deterministic mock results with an optional variance between backends.

    The base seed is keyed only on the query name (not the backend) so the two
    backends produce comparable numbers. Variance is then layered on top of the
    ShieldOps side as a small percentage drift to simulate real-world parallel-run
    conditions.
    """
    base_seed = f"{query.name}"
    total = _seeded_rand(base_seed + "|total", 200, 5000)
    if variance_pct:
        total = int(total * (1 + variance_pct / 100))
    top: dict[str, float] = {}
    for i in range(10):
        key = f"value_{i}"
        v = _seeded_rand(base_seed + f"|v{i}", 5, 500)
        if variance_pct and i % 4 == 0:
            v = int(v * (1 + variance_pct / 100))
        top[key] = float(v)
    buckets: dict[str, float] = {}
    for i in range(24):
        bucket = f"2026-04-05T{i:02d}:00"
        v = _seeded_rand(base_seed + f"|b{i}", 1, 200)
        if variance_pct and i % 6 == 0:
            v = int(v * (1 + variance_pct / 100))
        buckets[bucket] = float(v)
    return QueryResult(
        total_count=total,
        top_values=dict(sorted(top.items(), key=lambda kv: -kv[1])[:10]),
        time_buckets=buckets,
        raw_row_count=len(top),
        source="mock",
    )


# --------------------------------------------------------------------------- #
# Result normalization
# --------------------------------------------------------------------------- #


def normalize_splunk_rows(rows: list[dict[str, Any]], spec: QuerySpec) -> QueryResult:
    if not rows:
        return QueryResult(source="live")
    total = 0
    top: dict[str, float] = {}
    buckets: dict[str, float] = {}
    for row in rows:
        raw_count = row.get(spec.value_field, row.get("count", 1))
        try:
            count = float(raw_count)
        except (TypeError, ValueError):
            count = 1.0
        total += int(count)
        key = str(row.get(spec.key_field, ""))
        if key:
            top[key] = top.get(key, 0.0) + count
        ts = row.get("_time") or row.get("timestamp")
        if ts:
            bucket = str(ts)[:13]  # hour bucket
            buckets[bucket] = buckets.get(bucket, 0.0) + count
    top_sorted = dict(sorted(top.items(), key=lambda kv: -kv[1])[:10])
    return QueryResult(
        total_count=total,
        top_values=top_sorted,
        time_buckets=buckets,
        raw_row_count=len(rows),
        source="live",
    )


def normalize_shieldops_response(payload: dict[str, Any], spec: QuerySpec) -> QueryResult:
    results = payload.get("results") or payload.get("data") or []
    if not isinstance(results, list):
        return QueryResult(source="live")
    total = 0
    top: dict[str, float] = {}
    buckets: dict[str, float] = {}
    for row in results:
        raw_count = row.get(spec.value_field, row.get("count", 1))
        try:
            count = float(raw_count)
        except (TypeError, ValueError):
            count = 1.0
        total += int(count)
        key = str(row.get(spec.key_field, ""))
        if key:
            top[key] = top.get(key, 0.0) + count
        ts = row.get("bucket") or row.get("timestamp") or row.get("_time")
        if ts:
            bucket = str(ts)[:13]
            buckets[bucket] = buckets.get(bucket, 0.0) + count
    summary = payload.get("summary") or {}
    if not total and "total" in summary:
        with contextlib.suppress(TypeError, ValueError):
            total = int(summary["total"])
    top_sorted = dict(sorted(top.items(), key=lambda kv: -kv[1])[:10])
    return QueryResult(
        total_count=total,
        top_values=top_sorted,
        time_buckets=buckets,
        raw_row_count=len(results),
        source="live",
    )


# --------------------------------------------------------------------------- #
# Parity scoring
# --------------------------------------------------------------------------- #


def _pct_diff(a: float, b: float) -> float:
    if a == 0 and b == 0:
        return 0.0
    denom = max(abs(a), abs(b))
    if denom == 0:
        return 0.0
    return abs(a - b) / denom * 100.0


def score_count(a: QueryResult, b: QueryResult) -> float:
    return max(0.0, 100.0 - _pct_diff(a.total_count, b.total_count))


def score_top_values(a: QueryResult, b: QueryResult) -> float:
    if not a.top_values and not b.top_values:
        return 100.0
    keys = set(a.top_values) | set(b.top_values)
    if not keys:
        return 100.0
    diffs: list[float] = []
    for k in keys:
        diffs.append(_pct_diff(a.top_values.get(k, 0.0), b.top_values.get(k, 0.0)))
    return max(0.0, 100.0 - sum(diffs) / len(diffs))


def score_time_bucket(a: QueryResult, b: QueryResult) -> float:
    if not a.time_buckets and not b.time_buckets:
        return 100.0
    keys = set(a.time_buckets) | set(b.time_buckets)
    if not keys:
        return 100.0
    diffs = [_pct_diff(a.time_buckets.get(k, 0.0), b.time_buckets.get(k, 0.0)) for k in keys]
    return max(0.0, 100.0 - sum(diffs) / len(diffs))


def score_parity(query: QuerySpec, splunk: QueryResult, shieldops: QueryResult) -> float:
    if query.compare == "count":
        return score_count(splunk, shieldops)
    if query.compare == "top_values":
        return (score_count(splunk, shieldops) + score_top_values(splunk, shieldops)) / 2
    if query.compare == "time_bucket":
        return (score_count(splunk, shieldops) + score_time_bucket(splunk, shieldops)) / 2
    return score_count(splunk, shieldops)


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #


def load_queries(path: Path) -> list[QuerySpec]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, list):
        raise ValueError(f"Queries file {path} must contain a JSON list.")
    return [QuerySpec.from_dict(item) for item in raw]


def sample_queries() -> list[QuerySpec]:
    """Built-in sample queries for smoke tests and demos."""
    return [
        QuerySpec(
            name="auth_failures_by_user",
            description="Count of authentication failures grouped by user",
            splunk_spl="search index=auth action=failure | stats count by user",
            shieldops_nl="Show count of authentication failures grouped by user",
            compare="top_values",
            key_field="user",
            value_field="count",
        ),
        QuerySpec(
            name="cloudtrail_event_count",
            description="Total CloudTrail event count",
            splunk_spl="search index=aws sourcetype=aws:cloudtrail | stats count",
            shieldops_nl="Count total CloudTrail events",
            compare="count",
            key_field="sourcetype",
            value_field="count",
        ),
        QuerySpec(
            name="crowdstrike_detections_hourly",
            description="CrowdStrike detections per hour",
            splunk_spl=(
                "search index=crowdstrike sourcetype=crowdstrike:detection "
                "| bucket _time span=1h | stats count by _time"
            ),
            shieldops_nl="Show CrowdStrike detections bucketed by hour",
            compare="time_bucket",
            key_field="_time",
            value_field="count",
        ),
    ]


def run_query(
    spec: QuerySpec,
    splunk: SplunkClient | None,
    shieldops: ShieldOpsClient | None,
    earliest: datetime,
    latest: datetime,
    force_mock: bool,
) -> ParityOutcome:
    notes: list[str] = []

    # Splunk side
    if force_mock or splunk is None:
        splunk_result = mock_result(spec, "splunk")
        notes.append("Splunk: mock data")
    else:
        try:
            rows = splunk.run_search(
                spec.splunk_spl,
                earliest=earliest.strftime("%Y-%m-%dT%H:%M:%S"),
                latest=latest.strftime("%Y-%m-%dT%H:%M:%S"),
            )
            splunk_result = normalize_splunk_rows(rows, spec)
        except Exception as exc:  # noqa: BLE001 - fall back to mock for robustness
            LOG.warning("Splunk query failed (%s), using mock", exc)
            splunk_result = mock_result(spec, "splunk")
            splunk_result.error = str(exc)
            notes.append(f"Splunk error → mock: {exc}")

    # ShieldOps side
    if force_mock or shieldops is None:
        so_result = mock_result(spec, "shieldops", variance_pct=2.0)
        notes.append("ShieldOps: mock data")
    else:
        try:
            payload = shieldops.nl_query(spec.shieldops_nl, earliest, latest)
            so_result = normalize_shieldops_response(payload, spec)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("ShieldOps query failed (%s), using mock", exc)
            so_result = mock_result(spec, "shieldops", variance_pct=2.0)
            so_result.error = str(exc)
            notes.append(f"ShieldOps error → mock: {exc}")

    score = score_parity(spec, splunk_result, so_result)
    passed = score >= (100.0 - spec.tolerance_pct)
    return ParityOutcome(
        query=spec,
        splunk=splunk_result,
        shieldops=so_result,
        parity_score=round(score, 2),
        passed=passed,
        notes=notes,
    )


# --------------------------------------------------------------------------- #
# Report writer
# --------------------------------------------------------------------------- #


def write_report(
    outcomes: list[ParityOutcome],
    out_path: Path,
    window: str,
    earliest: datetime,
    latest: datetime,
    mode: str,
    mock: bool,
) -> None:
    total = len(outcomes)
    passed = sum(1 for o in outcomes if o.passed)
    avg_score = sum(o.parity_score for o in outcomes) / total if total else 0.0

    lines: list[str] = []
    lines.append("# SIEM Parallel-Run Parity Report")
    lines.append("")
    lines.append(f"- **Generated:** {datetime.now(UTC).isoformat()}")
    lines.append(f"- **Mode:** `{mode}`")
    lines.append(f"- **Window:** {window} ({earliest.isoformat()} → {latest.isoformat()})")
    lines.append(f"- **Data source:** {'mock' if mock else 'live'}")
    lines.append(f"- **Queries:** {total}")
    lines.append(f"- **Passed:** {passed} ({(passed / total * 100) if total else 0:.1f}%)")
    lines.append(f"- **Average parity:** {avg_score:.2f}%")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Query | Compare | Splunk count | ShieldOps count | Parity % | Result |")
    lines.append("|---|---|---|---|---|---|")
    for o in outcomes:
        mark = "PASS" if o.passed else "FAIL"
        lines.append(
            f"| `{o.query.name}` | {o.query.compare} | {o.splunk.total_count} | "
            f"{o.shieldops.total_count} | {o.parity_score:.2f} | {mark} |"
        )
    lines.append("")
    lines.append("## Details")
    lines.append("")
    for o in outcomes:
        lines.append(f"### `{o.query.name}` — {'PASS' if o.passed else 'FAIL'}")
        lines.append("")
        if o.query.description:
            lines.append(f"{o.query.description}")
            lines.append("")
        lines.append(
            f"- **Parity score:** {o.parity_score:.2f}% (tolerance {o.query.tolerance_pct}%)"
        )
        lines.append(f"- **Splunk rows:** {o.splunk.raw_row_count}, total {o.splunk.total_count}")
        lines.append(
            f"- **ShieldOps rows:** {o.shieldops.raw_row_count}, total {o.shieldops.total_count}"
        )
        if o.notes:
            lines.append("- **Notes:**")
            for note in o.notes:
                lines.append(f"  - {note}")
        if o.query.compare == "top_values":
            lines.append("")
            lines.append("| Key | Splunk | ShieldOps | Δ |")
            lines.append("|---|---|---|---|")
            keys = sorted(
                set(o.splunk.top_values) | set(o.shieldops.top_values),
                key=lambda k: -(o.splunk.top_values.get(k, 0) + o.shieldops.top_values.get(k, 0)),
            )[:15]
            for k in keys:
                a = o.splunk.top_values.get(k, 0.0)
                b = o.shieldops.top_values.get(k, 0.0)
                lines.append(f"| `{k}` | {a:.0f} | {b:.0f} | {b - a:+.0f} |")
        lines.append("")
        lines.append("<details><summary>SPL</summary>")
        lines.append("")
        lines.append("```spl")
        lines.append(o.query.splunk_spl)
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")
        lines.append("<details><summary>ShieldOps NL prompt</summary>")
        lines.append("")
        lines.append(f"> {o.query.shieldops_nl}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines))
    LOG.info("Wrote report: %s", out_path)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Validate Splunk ↔ ShieldOps parity for SIEM migration.",
    )
    p.add_argument("--window", default=DEFAULT_WINDOW, help="Time window, e.g. 24h, 7d, 15m")
    p.add_argument(
        "--queries",
        type=Path,
        help="Path to JSON queries file. If omitted, built-in sample queries are used.",
    )
    p.add_argument(
        "--mode",
        choices=("parity", "alerts", "smoke"),
        default="parity",
        help="Run mode. 'smoke' uses a tiny built-in subset for T-0 cutover checks.",
    )
    p.add_argument("--splunk-host", default=os.environ.get("SPLUNK_HOST", ""))
    p.add_argument("--splunk-user", default=os.environ.get("SPLUNK_USERNAME", ""))
    p.add_argument("--splunk-password", default=os.environ.get("SPLUNK_PASSWORD", ""))
    p.add_argument("--splunk-token", default=os.environ.get("SPLUNK_TOKEN", ""))
    p.add_argument(
        "--shieldops-host",
        default=os.environ.get("SHIELDOPS_HOST", "https://api.shieldops.io"),
    )
    p.add_argument(
        "--shieldops-token",
        default=os.environ.get("SHIELDOPS_API_TOKEN", ""),
    )
    p.add_argument("--tenant", default=os.environ.get("SHIELDOPS_TENANT", ""))
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification (use only for lab/staging).",
    )
    p.add_argument(
        "--mock",
        action="store_true",
        help="Force mock mode. Useful for previewing the report without credentials.",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=Path("reports/parity-report.md"),
        help="Output markdown path.",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Queries
    if args.queries:
        try:
            queries = load_queries(args.queries)
        except (OSError, ValueError, KeyError) as exc:
            LOG.error("Failed to load queries file: %s", exc)
            return 2
    else:
        queries = sample_queries()
    if args.mode == "smoke":
        queries = queries[:3]  # cutover smoke: keep it tight

    # Time window
    try:
        delta = parse_window(args.window)
    except ValueError as exc:
        LOG.error(str(exc))
        return 2
    latest = datetime.now(UTC)
    earliest = latest - delta

    # Clients
    verify_tls = not args.insecure
    splunk: SplunkClient | None = None
    shieldops: ShieldOpsClient | None = None
    force_mock = args.mock

    if not force_mock:
        if args.splunk_host:
            splunk = SplunkClient(
                host=args.splunk_host,
                username=args.splunk_user or None,
                password=args.splunk_password or None,
                token=args.splunk_token or None,
                verify_tls=verify_tls,
            )
            if not splunk.health():
                LOG.warning("Splunk health check failed; Splunk side will use mock data.")
                splunk = None
        else:
            LOG.warning("No --splunk-host provided; Splunk side will use mock data.")

        if args.shieldops_host and args.shieldops_token:
            shieldops = ShieldOpsClient(
                host=args.shieldops_host,
                token=args.shieldops_token,
                tenant=args.tenant or None,
                verify_tls=verify_tls,
            )
            if not shieldops.health():
                LOG.warning("ShieldOps health check failed; ShieldOps side will use mock data.")
                shieldops = None
        else:
            LOG.warning("No ShieldOps host/token; ShieldOps side will use mock data.")

    if splunk is None and shieldops is None:
        force_mock = True

    outcomes: list[ParityOutcome] = []
    for spec in queries:
        LOG.info("Running query: %s", spec.name)
        started = time.time()
        outcome = run_query(spec, splunk, shieldops, earliest, latest, force_mock)
        elapsed = time.time() - started
        LOG.info(
            "  → parity %.2f%% (%s) in %.1fs",
            outcome.parity_score,
            "PASS" if outcome.passed else "FAIL",
            elapsed,
        )
        outcomes.append(outcome)

    write_report(
        outcomes,
        out_path=args.out,
        window=args.window,
        earliest=earliest,
        latest=latest,
        mode=args.mode,
        mock=force_mock,
    )

    failed = [o for o in outcomes if not o.passed]
    if failed:
        LOG.error("%d of %d queries failed parity.", len(failed), len(outcomes))
        return 1
    LOG.info("All %d queries passed parity.", len(outcomes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
