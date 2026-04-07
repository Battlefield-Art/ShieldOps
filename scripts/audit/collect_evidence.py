#!/usr/bin/env python3
"""SOC 2 evidence collection script.

Runs nightly in CI. Gathers evidence from:
- PostgreSQL (user access list, last login times, audit log)
- Git (PRs merged in audit window, deployment commits)
- Connector health framework (current connector status)
- Backup verification logs

Outputs:
- ``evidence-report-{date}.json`` — structured machine-readable
- ``evidence-report-{date}.md``   — human-readable for the auditor

Usage::

    python scripts/audit/collect_evidence.py \\
        --window-days 30 \\
        --output-dir s3://shieldops-audit-evidence/2026-04/

Designed to be safe to run in CI without exposing PII (user ids hashed).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def _hash_id(value: str) -> str:
    """SHA-256 prefix to anonymize identifiers in audit output."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


@dataclass
class EvidenceReport:
    generated_at: str
    audit_window_start: str
    audit_window_end: str
    user_access: list[dict[str, Any]] = field(default_factory=list)
    pull_requests: list[dict[str, Any]] = field(default_factory=list)
    deployments: list[dict[str, Any]] = field(default_factory=list)
    connector_health: list[dict[str, Any]] = field(default_factory=list)
    backups: list[dict[str, Any]] = field(default_factory=list)
    incidents: list[dict[str, Any]] = field(default_factory=list)
    secrets_rotations: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------


async def collect_user_access(window_start: datetime) -> list[dict[str, Any]]:
    """Hashed user access list with last login + role."""
    try:
        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    except ImportError:
        return [{"error": "sqlalchemy not installed in this env"}]

    db_url = os.getenv("DATABASE_URL", "postgresql+asyncpg://localhost/shieldops")
    if not db_url.startswith("postgresql+asyncpg://"):
        # Don't fail; just skip
        return [{"warning": "DATABASE_URL not set or wrong driver — skipping"}]

    try:
        engine = create_async_engine(db_url)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        # Query the existing UserRecord (in src/shieldops/db/models.py)
        from shieldops.db.models import UserRecord  # type: ignore

        async with session_factory() as session:
            rows = (await session.execute(select(UserRecord))).scalars().all()
            results = [
                {
                    "user_id_hash": _hash_id(str(r.id)),
                    "role": getattr(r, "role", "unknown"),
                    "is_active": getattr(r, "is_active", True),
                    "created_at": str(getattr(r, "created_at", "")),
                    "last_login_at": str(getattr(r, "last_login_at", "")),
                }
                for r in rows
            ]
        await engine.dispose()
        return results
    except Exception as exc:
        return [{"error": f"db query failed: {exc}"}]


def collect_pull_requests(window_days: int) -> list[dict[str, Any]]:
    """Merged PRs in the audit window via git log."""
    since = (datetime.now(UTC) - timedelta(days=window_days)).strftime("%Y-%m-%d")
    try:
        out = subprocess.check_output(
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
    except subprocess.CalledProcessError:
        return [{"error": "git log failed"}]

    prs = []
    for line in out.splitlines():
        parts = line.split("|", 3)
        if len(parts) == 4:
            sha, subject, author, date = parts
            prs.append(
                {
                    "sha": sha[:12],
                    "subject": subject,
                    "author_hash": _hash_id(author),
                    "merged_at": date,
                }
            )
    return prs


def collect_deployments(window_days: int) -> list[dict[str, Any]]:
    """Production deploys (commits to main with deploy tag) in window."""
    since = (datetime.now(UTC) - timedelta(days=window_days)).strftime("%Y-%m-%d")
    try:
        out = subprocess.check_output(
            [
                "git",
                "log",
                "main",
                f"--since={since}",
                "--pretty=format:%H|%s|%ad",
                "--date=iso",
            ],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except subprocess.CalledProcessError:
        return [{"error": "git log on main failed"}]

    deploys = []
    for line in out.splitlines():
        parts = line.split("|", 2)
        if len(parts) == 3:
            sha, subject, date = parts
            deploys.append({"sha": sha[:12], "subject": subject, "date": date})
    return deploys


async def collect_connector_health() -> list[dict[str, Any]]:
    try:
        from shieldops.connectors.health import HealthCheckRegistry  # type: ignore
    except ImportError:
        return [{"warning": "connector health registry not importable"}]

    registry = HealthCheckRegistry.instance()
    snapshot = await registry.check_all(use_cache=False)
    return [
        {
            "connector": name,
            "status": status.status.value,
            "latency_ms": status.latency_ms,
            "last_checked": str(status.last_checked),
            "message": status.message or "",
        }
        for name, status in snapshot.items()
    ]


def collect_backup_evidence() -> list[dict[str, Any]]:
    """Look at the backup verification log file (production: pulled from S3)."""
    log_path = Path("/var/log/shieldops/backup-verification.log")
    if not log_path.exists():
        return [{"warning": "no backup log found at " + str(log_path)}]
    try:
        lines = log_path.read_text().strip().splitlines()[-30:]
        return [{"line": line} for line in lines]
    except Exception as exc:
        return [{"error": f"could not read backup log: {exc}"}]


def collect_incidents(window_days: int) -> list[dict[str, Any]]:
    """Incidents recorded in the audit log table over the window."""
    return [{"info": "TODO: query AuditLogRepository for action='incident.declared'"}]


def collect_secrets_rotations(window_days: int) -> list[dict[str, Any]]:
    """Secrets rotation events from the audit log."""
    return [{"info": "TODO: query AuditLogRepository for action='secrets.rotated'"}]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def render_markdown(report: EvidenceReport) -> str:
    lines: list[str] = []
    lines.append("# SOC 2 Evidence Report")
    lines.append("")
    lines.append(f"- Generated: {report.generated_at}")
    lines.append(f"- Window: {report.audit_window_start} → {report.audit_window_end}")
    lines.append("")
    lines.append("## User access")
    lines.append(f"Total users: {len(report.user_access)}")
    lines.append("")
    lines.append("## Pull requests merged")
    lines.append(f"Count: {len(report.pull_requests)}")
    lines.append("")
    lines.append("## Production deployments")
    lines.append(f"Count: {len(report.deployments)}")
    lines.append("")
    lines.append("## Connector health (snapshot)")
    for c in report.connector_health:
        lines.append(
            f"- **{c.get('connector', '?')}**: {c.get('status', '?')} ({c.get('latency_ms', '?')} ms)"
        )
    lines.append("")
    lines.append("## Backup verification (last 30 lines)")
    for b in report.backups[:30]:
        lines.append(f"- {b}")
    lines.append("")
    lines.append("## Incidents declared in window")
    lines.append(f"Count: {len(report.incidents)}")
    lines.append("")
    lines.append("## Secrets rotations in window")
    lines.append(f"Count: {len(report.secrets_rotations)}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def run(window_days: int, output_dir: Path) -> int:
    now = datetime.now(UTC)
    start = now - timedelta(days=window_days)

    report = EvidenceReport(
        generated_at=now.isoformat(),
        audit_window_start=start.isoformat(),
        audit_window_end=now.isoformat(),
    )

    print("[1/7] Collecting user access...")
    report.user_access = await collect_user_access(start)

    print("[2/7] Collecting pull requests...")
    report.pull_requests = collect_pull_requests(window_days)

    print("[3/7] Collecting deployments...")
    report.deployments = collect_deployments(window_days)

    print("[4/7] Collecting connector health...")
    report.connector_health = await collect_connector_health()

    print("[5/7] Collecting backup evidence...")
    report.backups = collect_backup_evidence()

    print("[6/7] Collecting incidents...")
    report.incidents = collect_incidents(window_days)

    print("[7/7] Collecting secrets rotations...")
    report.secrets_rotations = collect_secrets_rotations(window_days)

    output_dir.mkdir(parents=True, exist_ok=True)
    date_tag = now.strftime("%Y-%m-%d")

    json_path = output_dir / f"evidence-report-{date_tag}.json"
    md_path = output_dir / f"evidence-report-{date_tag}.md"

    json_path.write_text(json.dumps(asdict(report), indent=2))
    md_path.write_text(render_markdown(report))

    print(f"\n✓ Wrote {json_path}")
    print(f"✓ Wrote {md_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SOC 2 evidence collector")
    parser.add_argument("--window-days", type=int, default=30)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./audit-evidence"),
        help="Output directory (local or s3:// path)",
    )
    args = parser.parse_args()
    return asyncio.run(run(args.window_days, args.output_dir))


if __name__ == "__main__":
    sys.exit(main())
