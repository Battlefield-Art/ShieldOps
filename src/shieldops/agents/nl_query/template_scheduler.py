"""Scheduled execution of SOC templates with webhook delivery (#4 Round 3).

Lightweight, dependency-injected scheduler. The owning service (API lifespan,
Celery beat, or a dedicated worker) is expected to call :meth:`run_due` on a
fixed cadence (e.g. every 30 seconds). Each registered :class:`ScheduledTemplate`
fires its named template through the injected ``run_template`` callable, then
posts the result to the configured webhook URL.

Failures from individual templates are logged and isolated — they never abort
the rest of the batch.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


RunTemplateFn = Callable[..., Awaitable[Any]]
PostWebhookFn = Callable[[str, dict[str, Any]], Awaitable[None]]


@dataclass
class ScheduledTemplate:
    """A single registered template schedule."""

    template_id: str
    org_id: str
    interval_seconds: int
    webhook_url: str
    next_run: datetime
    last_run: datetime | None = None
    failures: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


class TemplateScheduler:
    """In-process SOC-template scheduler with webhook delivery."""

    def __init__(
        self,
        *,
        run_template: RunTemplateFn,
        post_webhook: PostWebhookFn,
    ) -> None:
        self._run_template = run_template
        self._post_webhook = post_webhook
        self.schedules: list[ScheduledTemplate] = []

    def register(
        self,
        *,
        template_id: str,
        org_id: str,
        interval_seconds: int,
        webhook_url: str,
    ) -> ScheduledTemplate:
        if interval_seconds <= 0:
            raise ValueError(f"interval_seconds must be positive, got {interval_seconds}")
        sched = ScheduledTemplate(
            template_id=template_id,
            org_id=org_id,
            interval_seconds=interval_seconds,
            webhook_url=webhook_url,
            next_run=datetime.now(UTC) + timedelta(seconds=interval_seconds),
        )
        self.schedules.append(sched)
        logger.info(
            "template_scheduler.registered",
            template_id=template_id,
            org_id=org_id,
            interval_seconds=interval_seconds,
        )
        return sched

    async def run_due(self, *, now: datetime | None = None) -> int:
        """Fire every schedule whose ``next_run <= now``. Returns count fired."""
        current = now or datetime.now(UTC)
        fired = 0
        for sched in self.schedules:
            if sched.next_run > current:
                continue
            try:
                result = await self._run_template(
                    template_id=sched.template_id,
                    org_id=sched.org_id,
                )
                await self._post_webhook(
                    sched.webhook_url,
                    {
                        "template_id": sched.template_id,
                        "org_id": sched.org_id,
                        "fired_at": current.isoformat(),
                        "result": result,
                    },
                )
                fired += 1
                sched.last_run = current
            except Exception as exc:  # noqa: BLE001 — isolate per-schedule errors
                sched.failures += 1
                logger.error(
                    "template_scheduler.failed",
                    template_id=sched.template_id,
                    org_id=sched.org_id,
                    failures=sched.failures,
                    error=str(exc),
                )
            finally:
                sched.next_run = current + timedelta(seconds=sched.interval_seconds)
        return fired
