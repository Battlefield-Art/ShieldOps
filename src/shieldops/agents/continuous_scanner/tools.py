"""Tool functions for the Continuous Scanner Agent."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.continuous_scanner.models import (
    DueScan,
    ScanDispatch,
    ScanProgress,
    ScanResult,
    ScanSchedule,
    ScanType,
)

logger = structlog.get_logger()


class ContinuousScannerToolkit:
    """Toolkit for continuous security scan scheduling."""

    def __init__(
        self,
        schedule_store: Any | None = None,
        agent_registry: Any | None = None,
        result_store: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._schedule_store = schedule_store
        self._agent_registry = agent_registry
        self._result_store = result_store
        self._repository = repository

    async def load_schedules(
        self,
        tenant_id: str,
    ) -> list[ScanSchedule]:
        """Load scan schedules for tenant."""
        logger.info(
            "continuous_scanner.load_schedules",
            tenant_id=tenant_id,
        )
        if self._schedule_store is not None:
            try:
                return await self._schedule_store.list(tenant_id)
            except Exception:
                logger.warning("continuous_scanner.load_fallback")
        return []

    async def check_due_scans(
        self,
        schedules: list[ScanSchedule],
    ) -> list[DueScan]:
        """Determine which scans are due."""
        logger.info(
            "continuous_scanner.check_due",
            schedule_count=len(schedules),
        )
        due: list[DueScan] = []
        now = datetime.now(UTC).isoformat()
        for sched in schedules:
            if not sched.enabled:
                continue
            is_due = not sched.next_run_at or sched.next_run_at <= now
            if is_due:
                due.append(
                    DueScan(
                        schedule_id=sched.id,
                        scan_type=sched.scan_type,
                        agent_name=sched.agent_name,
                        target_assets=(sched.target_assets),
                        overdue_minutes=0,
                        priority=(1 if sched.scan_type == ScanType.COMPLIANCE else 2),
                    )
                )
        due.sort(key=lambda d: d.priority)
        return due

    async def dispatch_scans(
        self,
        due_scans: list[DueScan],
        tenant_id: str,
    ) -> list[ScanDispatch]:
        """Dispatch due scans to agents."""
        logger.info(
            "continuous_scanner.dispatch",
            due_count=len(due_scans),
        )
        dispatched: list[ScanDispatch] = []
        now = datetime.now(UTC).isoformat()
        for scan in due_scans:
            dispatch_id = f"dsp-{uuid4().hex[:8]}"
            if self._agent_registry is not None:
                try:
                    await self._agent_registry.run(scan.agent_name, tenant_id)
                except Exception:
                    logger.warning(
                        "continuous_scanner.dispatch_err",
                        agent=scan.agent_name,
                    )
            dispatched.append(
                ScanDispatch(
                    schedule_id=scan.schedule_id,
                    agent_name=scan.agent_name,
                    dispatch_id=dispatch_id,
                    status="dispatched",
                    dispatched_at=now,
                )
            )
        return dispatched

    async def monitor_progress(
        self,
        dispatched: list[ScanDispatch],
    ) -> list[ScanProgress]:
        """Monitor progress of dispatched scans."""
        logger.info(
            "continuous_scanner.monitor",
            dispatched_count=len(dispatched),
        )
        progress: list[ScanProgress] = []
        for d in dispatched:
            if self._agent_registry is not None:
                try:
                    s = await self._agent_registry.status(d.agent_name)
                    progress.append(
                        ScanProgress(
                            dispatch_id=d.dispatch_id,
                            agent_name=d.agent_name,
                            status=s.get("status", "running"),
                            progress_pct=s.get("progress", 0.0),
                            findings_so_far=s.get("findings", 0),
                        )
                    )
                    continue
                except Exception:
                    logger.warning(
                        "continuous_scanner.monitor_err",
                        agent=d.agent_name,
                    )
            progress.append(
                ScanProgress(
                    dispatch_id=d.dispatch_id,
                    agent_name=d.agent_name,
                    status="completed",
                    progress_pct=100.0,
                )
            )
        return progress

    async def collect_results(
        self,
        progress: list[ScanProgress],
    ) -> list[ScanResult]:
        """Collect final results from scans."""
        logger.info(
            "continuous_scanner.collect_results",
            progress_count=len(progress),
        )
        results: list[ScanResult] = []
        for p in progress:
            if self._result_store is not None:
                try:
                    r = await self._result_store.get(p.dispatch_id)
                    results.append(
                        ScanResult(
                            dispatch_id=p.dispatch_id,
                            agent_name=p.agent_name,
                            status=r.get("status", "completed"),
                            findings_count=r.get("findings", 0),
                            critical_count=r.get("critical", 0),
                            high_count=r.get("high", 0),
                            duration_ms=r.get("duration_ms", 0),
                        )
                    )
                    continue
                except Exception:
                    logger.warning("continuous_scanner.result_err")
            results.append(
                ScanResult(
                    dispatch_id=p.dispatch_id,
                    agent_name=p.agent_name,
                    status=p.status,
                    findings_count=p.findings_so_far,
                    duration_ms=p.elapsed_ms,
                )
            )
        return results
