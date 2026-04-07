#!/usr/bin/env python3
"""SOC 2 evidence collection script.

Gathers audit-relevant data from the ShieldOps production database, the
connector health framework, and (optionally) git, then writes a structured
report (JSON + Markdown) to an output directory. Designed to run on a real
Postgres database via SQLAlchemy and the existing connector health framework
at ``src/shieldops/connectors/health.py``.

Sections (each runnable independently with ``--section``):

* ``access``       — user roster, role, hashed identifiers, API key inventory.
* ``audit_log``    — sample of immutable audit-log entries in the window.
* ``changes``      — deployment events from the audit log + merged PRs from
                     git history (where the script can reach the git tree).
* ``incidents``    — war rooms opened in the window with severity + duration.
* ``secrets_rotation`` — secret-rotation events from the audit log.
* ``backups``      — backup_runs / restore_tests tables (queried via raw SQL
                     so the script does not require those models to exist as
                     ORM classes).
* ``connectors``   — current health snapshot from
                     ``HealthCheckRegistry.check_all()``.

Usage::

    # Default: full audit window (365 days), all sections.
    python scripts/audit/collect_evidence.py \\
        --out artifacts/soc2-2026q1/

    # Just the access review for a quarterly review.
    python scripts/audit/collect_evidence.py \\
        --section access \\
        --window quarterly \\
        --out artifacts/access-review-2026q2/

    # Post-offboarding verification: confirm a user has no residual access.
    python scripts/audit/collect_evidence.py \\
        --check-user alice@example.com

The output directory will contain:

* ``report.json``  — full structured report.
* ``report.md``    — human-readable summary suitable for sharing with auditors.
* ``users.csv``    — (access section) one row per user.
* ``api_keys.csv`` — (access section) one row per API key.

Hashing
-------
Personally identifiable values (email addresses, key prefixes, actor strings)
are SHA-256 hashed before being written to the report so the report can be
shared without exposing PII. The hash uses an HMAC keyed with
``$SOC2_REPORT_HMAC_KEY`` when set, otherwise an unkeyed SHA-256.

Exit codes
----------
* 0 — all requested sections collected.
* 1 — ``--check-user`` mode: residual access found.
* 2 — at least one section errored, or invalid arguments.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import hmac
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Optional imports — kept lazy so the script runs in environments where some
# dependencies are not installed (e.g., a sandboxed evidence-collection box).
# ---------------------------------------------------------------------------

try:
    from sqlalchemy import select, text
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )

    _SQLALCHEMY_AVAILABLE = True
except ImportError:  # pragma: no cover - optional
    _SQLALCHEMY_AVAILABLE = False

try:
    from shieldops.connectors.health import (  # type: ignore
        ConnectorStatus,
        HealthCheckRegistry,
    )
    from shieldops.db.models import (  # type: ignore
        APIKeyRecord,
        AuditLog,
        UserRecord,
        WarRoomRecord,
    )

    _SHIELDOPS_AVAILABLE = True
except ImportError:  # pragma: no cover - optional
    _SHIELDOPS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash(value: str | None) -> str:
    """SHA-256 (or HMAC-SHA-256) of a value, hex-encoded.

    Returns the literal string ``"<none>"`` for None or empty input so that
    downstream consumers do not confuse missing data with a real hash.
    """
    if not value:
        return "<none>"
    key = os.environ.get("SOC2_REPORT_HMAC_KEY", "").encode("utf-8")
    if key:
        return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _parse_window(spec: str | None) -> tuple[datetime, datetime]:
    """Parse a window like ``2026-01-01:2026-04-01`` or a preset.

    Presets:

    * ``quarterly`` — last 90 days.
    * ``monthly`` — last 30 days.
    * ``ytd`` — Jan 1 of current year through now.
    * ``audit`` — last 365 days (default for SOC 2 Type I observation period).
    """
    if spec is None:
        spec = "audit"
    now = _utcnow()
    if spec == "quarterly":
        return now - timedelta(days=90), now
    if spec == "monthly":
        return now - timedelta(days=30), now
    if spec == "audit":
        return now - timedelta(days=365), now
    if spec == "ytd":
        return datetime(now.year, 1, 1, tzinfo=UTC), now
    if ":" in spec:
        start_s, end_s = spec.split(":", 1)
        return (
            datetime.fromisoformat(start_s).replace(tzinfo=UTC),
            datetime.fromisoformat(end_s).replace(tzinfo=UTC),
        )
    raise ValueError(f"Unrecognized window spec: {spec!r}")


@dataclass
class SectionResult:
    """Container for one section of the report."""

    name: str
    status: str = "ok"  # ok | unavailable | error
    summary: dict[str, Any] = field(default_factory=dict)
    rows: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


# ---------------------------------------------------------------------------
# Database access
# ---------------------------------------------------------------------------


class _DBClient:
    """Thin wrapper around an async SQLAlchemy session for the script."""

    def __init__(self, database_url: str) -> None:
        if not _SQLALCHEMY_AVAILABLE:
            raise RuntimeError("SQLAlchemy is not installed in this environment")
        self._engine = create_async_engine(database_url, pool_size=5, max_overflow=0)
        self._sessionmaker = async_sessionmaker(self._engine, expire_on_commit=False)

    def session(self) -> AsyncSession:
        return self._sessionmaker()

    async def close(self) -> None:
        await self._engine.dispose()


# ---------------------------------------------------------------------------
# Section collectors
# ---------------------------------------------------------------------------


async def collect_access(db: _DBClient | None) -> SectionResult:
    section = SectionResult(name="access")
    if db is None or not _SHIELDOPS_AVAILABLE:
        section.status = "unavailable"
        section.summary["reason"] = "database or shieldops models not available"
        return section

    try:
        async with db.session() as s:
            user_rows = (await s.execute(select(UserRecord))).scalars().all()
            key_rows = (await s.execute(select(APIKeyRecord))).scalars().all()

        users: list[dict[str, Any]] = []
        for u in user_rows:
            users.append(
                {
                    "user_id": u.id,
                    "email_hash": _hash(u.email),
                    "name_hash": _hash(u.name),
                    "role": u.role,
                    "is_active": u.is_active,
                    "created_at": u.created_at.isoformat() if u.created_at else None,
                    "updated_at": u.updated_at.isoformat() if u.updated_at else None,
                }
            )

        api_keys: list[dict[str, Any]] = []
        now = _utcnow()
        for k in key_rows:
            expired = bool(k.expires_at and k.expires_at < now)
            stale_days: int | None
            if k.last_used_at:
                stale_days = (now - k.last_used_at).days
            elif k.created_at:
                stale_days = (now - k.created_at).days
            else:
                stale_days = None
            api_keys.append(
                {
                    "api_key_id": k.id,
                    "key_prefix_hash": _hash(k.key_prefix),
                    "user_id": k.user_id,
                    "organization_id": k.organization_id,
                    "name": k.name,
                    "scopes": list(k.scopes or []),
                    "is_active": k.is_active,
                    "expired": expired,
                    "stale_days": stale_days,
                    "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                    "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                    "created_at": k.created_at.isoformat() if k.created_at else None,
                }
            )

        active_users = sum(1 for u in users if u["is_active"])
        admins = sum(1 for u in users if u["role"] == "admin")
        operators = sum(1 for u in users if u["role"] == "operator")
        viewers = sum(1 for u in users if u["role"] == "viewer")
        active_keys = sum(1 for k in api_keys if k["is_active"] and not k["expired"])
        stale_keys = sum(
            1
            for k in api_keys
            if k["is_active"] and k["stale_days"] is not None and k["stale_days"] > 60
        )

        section.summary = {
            "users_total": len(users),
            "users_active": active_users,
            "users_disabled": len(users) - active_users,
            "admins": admins,
            "operators": operators,
            "viewers": viewers,
            "api_keys_total": len(api_keys),
            "api_keys_active": active_keys,
            "api_keys_stale_60d": stale_keys,
        }
        section.rows = [{"users": users}, {"api_keys": api_keys}]
    except SQLAlchemyError as exc:
        section.status = "error"
        section.error = f"db query failed: {exc}"
    return section


async def collect_audit_log(
    db: _DBClient | None,
    start: datetime,
    end: datetime,
    sample_limit: int = 500,
) -> SectionResult:
    section = SectionResult(name="audit_log")
    if db is None or not _SHIELDOPS_AVAILABLE:
        section.status = "unavailable"
        return section

    try:
        async with db.session() as s:
            stmt = (
                select(AuditLog)
                .where(AuditLog.timestamp >= start)
                .where(AuditLog.timestamp <= end)
                .order_by(AuditLog.timestamp.desc())
                .limit(sample_limit)
            )
            entries = (await s.execute(stmt)).scalars().all()

            count_stmt = text(
                "SELECT count(*) FROM audit_log WHERE timestamp >= :start AND timestamp <= :end"
            )
            total = (await s.execute(count_stmt, {"start": start, "end": end})).scalar_one()

        actions: dict[str, int] = {}
        outcomes: dict[str, int] = {}
        rows: list[dict[str, Any]] = []
        for e in entries:
            actions[e.action] = actions.get(e.action, 0) + 1
            outcomes[e.outcome] = outcomes.get(e.outcome, 0) + 1
            rows.append(
                {
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "agent_type": e.agent_type,
                    "action": e.action,
                    "target_resource": e.target_resource,
                    "environment": e.environment,
                    "risk_level": e.risk_level,
                    "policy_evaluation": e.policy_evaluation,
                    "approval_status": e.approval_status,
                    "outcome": e.outcome,
                    "actor_hash": _hash(e.actor),
                }
            )

        section.summary = {
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "total_in_window": int(total),
            "sampled": len(rows),
            "actions_breakdown": actions,
            "outcomes_breakdown": outcomes,
        }
        section.rows = rows
    except SQLAlchemyError as exc:
        section.status = "error"
        section.error = f"db query failed: {exc}"
    return section


async def collect_incidents(db: _DBClient | None, start: datetime, end: datetime) -> SectionResult:
    section = SectionResult(name="incidents")
    if db is None or not _SHIELDOPS_AVAILABLE:
        section.status = "unavailable"
        return section

    try:
        async with db.session() as s:
            stmt = (
                select(WarRoomRecord)
                .where(WarRoomRecord.created_at >= start)
                .where(WarRoomRecord.created_at <= end)
                .order_by(WarRoomRecord.created_at.desc())
            )
            rooms = (await s.execute(stmt)).scalars().all()

        sev_counts: dict[str, int] = {}
        durations_minutes: list[float] = []
        rows: list[dict[str, Any]] = []
        for r in rooms:
            sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1
            duration_min: float | None = None
            if r.resolved_at and r.created_at:
                duration_min = (r.resolved_at - r.created_at).total_seconds() / 60.0
                durations_minutes.append(duration_min)
            rows.append(
                {
                    "id": r.id,
                    "incident_id": r.incident_id,
                    "severity": r.severity,
                    "status": r.status,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
                    "duration_minutes": duration_min,
                    "escalation_level": r.escalation_level,
                    "has_post_mortem": bool(r.resolution_summary),
                }
            )

        avg_minutes = sum(durations_minutes) / len(durations_minutes) if durations_minutes else None
        section.summary = {
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "total_incidents": len(rooms),
            "by_severity": sev_counts,
            "avg_resolution_minutes": avg_minutes,
            "missing_post_mortem": sum(1 for row in rows if not row["has_post_mortem"]),
        }
        section.rows = rows
    except SQLAlchemyError as exc:
        section.status = "error"
        section.error = f"db query failed: {exc}"
    return section


async def collect_secrets_rotation(
    db: _DBClient | None, start: datetime, end: datetime
) -> SectionResult:
    section = SectionResult(name="secrets_rotation")
    if db is None or not _SHIELDOPS_AVAILABLE:
        section.status = "unavailable"
        return section

    try:
        async with db.session() as s:
            stmt = (
                select(AuditLog)
                .where(AuditLog.action == "secret_rotated")
                .where(AuditLog.timestamp >= start)
                .where(AuditLog.timestamp <= end)
                .order_by(AuditLog.timestamp.desc())
            )
            events = (await s.execute(stmt)).scalars().all()
        rows = [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "target_resource": e.target_resource,
                "outcome": e.outcome,
                "actor_hash": _hash(e.actor),
            }
            for e in events
        ]
        section.summary = {
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "total_rotations": len(rows),
        }
        section.rows = rows
    except SQLAlchemyError as exc:
        section.status = "error"
        section.error = f"db query failed: {exc}"
    return section


async def collect_changes(db: _DBClient | None, start: datetime, end: datetime) -> SectionResult:
    """Collect deployment events from the audit log + merged-PR list from git."""
    section = SectionResult(name="changes")
    deployments: list[dict[str, Any]] = []
    starts = completes = failures = 0

    if db is not None and _SHIELDOPS_AVAILABLE:
        try:
            async with db.session() as s:
                stmt = (
                    select(AuditLog)
                    .where(AuditLog.action.in_(["deployment_start", "deployment_complete"]))
                    .where(AuditLog.timestamp >= start)
                    .where(AuditLog.timestamp <= end)
                    .order_by(AuditLog.timestamp.asc())
                )
                events = (await s.execute(stmt)).scalars().all()
            for e in events:
                if e.action == "deployment_start":
                    starts += 1
                else:
                    completes += 1
                    if e.outcome != "success":
                        failures += 1
                deployments.append(
                    {
                        "id": e.id,
                        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                        "action": e.action,
                        "target_resource": e.target_resource,
                        "environment": e.environment,
                        "outcome": e.outcome,
                        "actor_hash": _hash(e.actor),
                    }
                )
        except SQLAlchemyError as exc:
            section.status = "error"
            section.error = f"db query failed: {exc}"
            return section

    # Git history is best-effort; the audit-evidence box may not have a clone.
    pr_rows: list[dict[str, Any]] = []
    git_error: str | None = None
    since = start.strftime("%Y-%m-%d")
    try:
        out = subprocess.check_output(  # noqa: S603,S607 - fixed args
            [
                "git",
                "log",
                "--merges",
                f"--since={since}",
                "--pretty=format:%H|%s|%an|%ad",
                "--date=iso",
            ],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in out.splitlines():
            parts = line.split("|", 3)
            if len(parts) == 4:
                sha, subject, author, date = parts
                pr_rows.append(
                    {
                        "sha": sha[:12],
                        "subject": subject,
                        "author_hash": _hash(author),
                        "merged_at": date,
                    }
                )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        git_error = str(exc)

    section.summary = {
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "deployment_starts": starts,
        "deployment_completes": completes,
        "failed_deployments": failures,
        "merged_prs": len(pr_rows),
        "git_error": git_error,
        "github_pr_evidence": "see procedures/deployment-approval.md for the PR sample procedure",
    }
    section.rows = [{"deployments": deployments}, {"merged_prs": pr_rows}]
    return section


async def collect_backups(db: _DBClient | None, start: datetime, end: datetime) -> SectionResult:
    section = SectionResult(name="backups")
    if db is None or not _SQLALCHEMY_AVAILABLE:
        section.status = "unavailable"
        return section

    # backup_runs and restore_tests are operational tables not in the SQLAlchemy
    # models module; query them via raw SQL so this works without a model dep.
    runs: list[Any] = []
    restores: list[Any] = []
    try:
        async with db.session() as s:
            try:
                runs = (
                    await s.execute(
                        text(
                            "SELECT started_at, completed_at, status, "
                            "size_bytes, sha256, target "
                            "FROM backup_runs "
                            "WHERE started_at >= :start AND started_at <= :end "
                            "ORDER BY started_at DESC LIMIT 200"
                        ),
                        {"start": start, "end": end},
                    )
                ).all()
            except SQLAlchemyError:
                runs = []
            try:
                restores = (
                    await s.execute(
                        text(
                            "SELECT run_at, backup_key, duration_seconds, "
                            "rows_verified, status "
                            "FROM restore_tests "
                            "WHERE run_at >= :start AND run_at <= :end "
                            "ORDER BY run_at DESC LIMIT 200"
                        ),
                        {"start": start, "end": end},
                    )
                ).all()
            except SQLAlchemyError:
                restores = []
    except SQLAlchemyError as exc:
        section.status = "error"
        section.error = f"db query failed: {exc}"
        return section

    backup_rows = [
        {
            "started_at": r[0].isoformat() if r[0] else None,
            "completed_at": r[1].isoformat() if r[1] else None,
            "status": r[2],
            "size_bytes": r[3],
            "sha256": r[4],
            "target": r[5],
        }
        for r in runs
    ]
    restore_rows = [
        {
            "run_at": r[0].isoformat() if r[0] else None,
            "backup_key": r[1],
            "duration_seconds": r[2],
            "rows_verified": r[3],
            "status": r[4],
        }
        for r in restores
    ]
    success = sum(1 for b in backup_rows if b["status"] == "success")
    restore_success = sum(1 for r in restore_rows if r["status"] == "success")

    section.summary = {
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "backup_runs": len(backup_rows),
        "backup_successes": success,
        "restore_tests": len(restore_rows),
        "restore_successes": restore_success,
    }
    section.rows = [{"backups": backup_rows}, {"restore_tests": restore_rows}]
    return section


async def collect_connectors() -> SectionResult:
    section = SectionResult(name="connectors")
    if not _SHIELDOPS_AVAILABLE:
        section.status = "unavailable"
        section.summary["reason"] = "shieldops package not importable"
        return section

    try:
        registry = HealthCheckRegistry()
        results = await registry.check_all()
    except Exception as exc:  # pragma: no cover - defensive
        section.status = "error"
        section.error = f"connector health check failed: {exc}"
        return section

    rows: list[dict[str, Any]] = []
    by_status: dict[str, int] = {}
    for name, status in results.items():
        by_status[status.status.value] = by_status.get(status.status.value, 0) + 1
        rows.append(
            {
                "connector": name,
                "status": status.status.value,
                "latency_ms": status.latency_ms,
                "message": status.message,
                "checked_at": status.last_checked.isoformat(),
            }
        )

    healthy = by_status.get(ConnectorStatus.HEALTHY.value, 0)
    section.summary = {
        "registered": len(results),
        "healthy": healthy,
        "degraded": by_status.get(ConnectorStatus.DEGRADED.value, 0),
        "unavailable": by_status.get(ConnectorStatus.UNAVAILABLE.value, 0),
        "checked_at": _utcnow().isoformat(),
    }
    section.rows = rows
    return section


# ---------------------------------------------------------------------------
# User-lookup mode (offboarding verification)
# ---------------------------------------------------------------------------


async def check_user(db: _DBClient, identifier: str) -> dict[str, Any]:
    """Confirm whether a user has any residual active access.

    Useful as a post-offboarding verification:
    ``python collect_evidence.py --check-user alice@example.com``
    """
    if not _SHIELDOPS_AVAILABLE:
        return {"status": "unavailable", "reason": "shieldops package not importable"}

    findings: dict[str, Any] = {
        "identifier_hash": _hash(identifier),
        "checked_at": _utcnow().isoformat(),
        "active_user_record": None,
        "active_api_keys": [],
        "recent_audit_actions": 0,
    }
    try:
        async with db.session() as s:
            user = (
                await s.execute(select(UserRecord).where(UserRecord.email == identifier))
            ).scalar_one_or_none()
            if user is not None:
                findings["active_user_record"] = {
                    "user_id": user.id,
                    "is_active": user.is_active,
                    "role": user.role,
                    "updated_at": user.updated_at.isoformat() if user.updated_at else None,
                }
                keys = (
                    (
                        await s.execute(
                            select(APIKeyRecord)
                            .where(APIKeyRecord.user_id == user.id)
                            .where(APIKeyRecord.is_active.is_(True))
                        )
                    )
                    .scalars()
                    .all()
                )
                findings["active_api_keys"] = [
                    {
                        "id": k.id,
                        "name": k.name,
                        "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                    }
                    for k in keys
                ]
                recent = (
                    await s.execute(
                        text(
                            "SELECT count(*) FROM audit_log "
                            "WHERE actor = :actor "
                            "AND timestamp >= now() - interval '7 days'"
                        ),
                        {"actor": identifier},
                    )
                ).scalar_one()
                findings["recent_audit_actions"] = int(recent)
    except SQLAlchemyError as exc:
        return {"status": "error", "error": str(exc)}

    clean = (
        findings["active_user_record"] is None or not findings["active_user_record"]["is_active"]
    ) and not findings["active_api_keys"]
    findings["clean"] = clean
    return findings


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------


def write_json_report(out_dir: Path, sections: list[SectionResult]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at": _utcnow().isoformat(),
        "tool": "scripts/audit/collect_evidence.py",
        "tool_version": "2.0",
        "sections": [asdict(s) for s in sections],
    }
    path = out_dir / "report.json"
    path.write_text(json.dumps(report, indent=2, default=str))
    return path


def write_markdown_report(out_dir: Path, sections: list[SectionResult]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# SOC 2 Evidence Collection Report")
    lines.append("")
    lines.append(f"Generated: {_utcnow().isoformat()}")
    lines.append("")
    lines.append(
        "Each section below corresponds to a section of the SOC 2 Type I audit. "
        "Personally identifiable values are SHA-256 hashed; raw identifiers can "
        "be re-derived from the production database with the audit-time HMAC "
        "key on file with Security."
    )
    lines.append("")
    for s in sections:
        lines.append(f"## {s.name}")
        lines.append("")
        lines.append(f"**Status:** `{s.status}`")
        if s.error:
            lines.append("")
            lines.append(f"**Error:** {s.error}")
        if s.summary:
            lines.append("")
            lines.append("**Summary:**")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(s.summary, indent=2, default=str))
            lines.append("```")
        lines.append("")
    path = out_dir / "report.md"
    path.write_text("\n".join(lines))
    return path


def write_access_csvs(out_dir: Path, access_section: SectionResult) -> None:
    if access_section.status != "ok" or not access_section.rows:
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    users: list[dict[str, Any]] = []
    api_keys: list[dict[str, Any]] = []
    for entry in access_section.rows:
        if "users" in entry:
            users = entry["users"]  # type: ignore[assignment]
        if "api_keys" in entry:
            api_keys = entry["api_keys"]  # type: ignore[assignment]
    if users:
        with (out_dir / "users.csv").open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(users[0].keys()))
            writer.writeheader()
            writer.writerows(users)
    if api_keys:
        with (out_dir / "api_keys.csv").open("w", newline="") as fh:
            for k in api_keys:
                k["scopes"] = json.dumps(k.get("scopes", []))
            writer = csv.DictWriter(fh, fieldnames=list(api_keys[0].keys()))
            writer.writeheader()
            writer.writerows(api_keys)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


async def run(
    sections: set[str],
    window: tuple[datetime, datetime],
    out_dir: Path,
    database_url: str | None,
) -> int:
    db: _DBClient | None = None
    if database_url and _SQLALCHEMY_AVAILABLE:
        db = _DBClient(database_url)
    elif database_url and not _SQLALCHEMY_AVAILABLE:
        print("WARNING: SQLAlchemy not installed; database sections will be skipped")

    start, end = window
    results: list[SectionResult] = []

    try:
        if "access" in sections:
            print("[access] collecting...")
            results.append(await collect_access(db))
        if "audit_log" in sections:
            print("[audit_log] collecting...")
            results.append(await collect_audit_log(db, start, end))
        if "changes" in sections:
            print("[changes] collecting...")
            results.append(await collect_changes(db, start, end))
        if "incidents" in sections:
            print("[incidents] collecting...")
            results.append(await collect_incidents(db, start, end))
        if "secrets_rotation" in sections:
            print("[secrets_rotation] collecting...")
            results.append(await collect_secrets_rotation(db, start, end))
        if "backups" in sections:
            print("[backups] collecting...")
            results.append(await collect_backups(db, start, end))
        if "connectors" in sections:
            print("[connectors] collecting...")
            results.append(await collect_connectors())
    finally:
        if db is not None:
            await db.close()

    json_path = write_json_report(out_dir, results)
    md_path = write_markdown_report(out_dir, results)
    for s in results:
        if s.name == "access":
            write_access_csvs(out_dir, s)

    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")

    if any(s.status == "error" for s in results):
        return 2
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Collect SOC 2 Type I evidence from ShieldOps production systems.",
    )
    p.add_argument(
        "--section",
        action="append",
        choices=[
            "all",
            "access",
            "changes",
            "backups",
            "connectors",
            "audit_log",
            "incidents",
            "secrets_rotation",
        ],
        help="Section(s) to collect; default is 'all'. May be repeated.",
    )
    p.add_argument(
        "--window",
        default="audit",
        help=(
            "Time window: 'audit' (last 365d, default), 'quarterly' (90d), "
            "'monthly' (30d), 'ytd', or an ISO range like 2026-01-01:2026-04-01."
        ),
    )
    p.add_argument(
        "--out",
        default="artifacts/soc2-evidence",
        help="Output directory for the report (created if missing).",
    )
    p.add_argument(
        "--database-url",
        default=os.environ.get("DATABASE_URL"),
        help="SQLAlchemy async database URL. Defaults to $DATABASE_URL.",
    )
    p.add_argument(
        "--check-user",
        help=(
            "Verification mode: confirm that a user has no residual active "
            "access. Prints a JSON verdict and exits. Used after offboarding."
        ),
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    if args.check_user:
        if not args.database_url:
            print("--check-user requires --database-url or DATABASE_URL", file=sys.stderr)
            return 2
        db = _DBClient(args.database_url)

        async def _go() -> int:
            try:
                result = await check_user(db, args.check_user)
            finally:
                await db.close()
            print(json.dumps(result, indent=2, default=str))
            return 0 if result.get("clean") else 1

        return asyncio.run(_go())

    sections_raw = args.section or ["all"]
    if "all" in sections_raw:
        sections = {
            "access",
            "audit_log",
            "changes",
            "incidents",
            "secrets_rotation",
            "backups",
            "connectors",
        }
    else:
        sections = set(sections_raw)

    window = _parse_window(args.window)
    out_dir = Path(args.out)
    return asyncio.run(run(sections, window, out_dir, args.database_url))


if __name__ == "__main__":
    sys.exit(main())
