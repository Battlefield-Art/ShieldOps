"""SOC template scheduled execution — TDD tests (#4 Round 3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from shieldops.agents.nl_query.template_scheduler import (
    ScheduledTemplate,
    TemplateScheduler,
)


class _FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def run_template(
        self, *, template_id: str, org_id: str, runner: Any = None
    ) -> dict[str, Any]:
        self.calls.append((template_id, org_id))
        return {"template_id": template_id, "rows": [{"x": 1}]}


class _FakeWebhook:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict[str, Any]]] = []

    async def post(self, url: str, payload: dict[str, Any]) -> None:
        self.posts.append((url, payload))


@pytest.fixture()
def runner() -> _FakeRunner:
    return _FakeRunner()


@pytest.fixture()
def webhook() -> _FakeWebhook:
    return _FakeWebhook()


@pytest.fixture()
def scheduler(runner: _FakeRunner, webhook: _FakeWebhook) -> TemplateScheduler:
    return TemplateScheduler(
        run_template=runner.run_template,
        post_webhook=webhook.post,
    )


class TestTemplateScheduler:
    def test_register_returns_schedule_with_next_run(self, scheduler: TemplateScheduler) -> None:
        sched = scheduler.register(
            template_id="daily_threat_briefing",
            org_id="org-a",
            interval_seconds=3600,
            webhook_url="https://hooks.example/abc",
        )
        assert isinstance(sched, ScheduledTemplate)
        assert sched.next_run is not None

    @pytest.mark.asyncio
    async def test_run_due_fires_template_past_next_run(
        self,
        scheduler: TemplateScheduler,
        runner: _FakeRunner,
        webhook: _FakeWebhook,
    ) -> None:
        scheduler.register(
            template_id="daily_threat_briefing",
            org_id="org-a",
            interval_seconds=60,
            webhook_url="https://hooks.example/abc",
        )
        # Force next_run into the past.
        for s in scheduler.schedules:
            s.next_run = datetime.now(UTC) - timedelta(seconds=1)

        fired = await scheduler.run_due(now=datetime.now(UTC))
        assert fired == 1
        assert runner.calls == [("daily_threat_briefing", "org-a")]
        assert len(webhook.posts) == 1
        url, payload = webhook.posts[0]
        assert url == "https://hooks.example/abc"
        assert payload["template_id"] == "daily_threat_briefing"
        assert payload["org_id"] == "org-a"
        assert "result" in payload

    @pytest.mark.asyncio
    async def test_run_due_skips_future_schedules(
        self, scheduler: TemplateScheduler, runner: _FakeRunner
    ) -> None:
        scheduler.register(
            template_id="t1",
            org_id="org-a",
            interval_seconds=3600,
            webhook_url="https://hooks.example/abc",
        )
        # Default next_run is "now + interval", so nothing is due.
        fired = await scheduler.run_due(now=datetime.now(UTC))
        assert fired == 0
        assert runner.calls == []

    @pytest.mark.asyncio
    async def test_run_due_advances_next_run_after_firing(
        self, scheduler: TemplateScheduler
    ) -> None:
        scheduler.register(
            template_id="t1",
            org_id="org-a",
            interval_seconds=60,
            webhook_url="https://hooks.example/abc",
        )
        s = scheduler.schedules[0]
        s.next_run = datetime.now(UTC) - timedelta(seconds=1)
        before = s.next_run
        await scheduler.run_due(now=datetime.now(UTC))
        assert s.next_run > before
        assert s.last_run is not None

    @pytest.mark.asyncio
    async def test_run_due_continues_when_one_template_fails(
        self, scheduler: TemplateScheduler, webhook: _FakeWebhook
    ) -> None:
        async def boom(*, template_id: str, org_id: str, runner: Any = None) -> Any:
            if template_id == "broken":
                raise RuntimeError("template exploded")
            return {"template_id": template_id, "rows": []}

        scheduler._run_template = boom  # type: ignore[assignment]
        scheduler.register(
            template_id="broken",
            org_id="org-a",
            interval_seconds=60,
            webhook_url="https://hooks.example/x",
        )
        scheduler.register(
            template_id="t1",
            org_id="org-a",
            interval_seconds=60,
            webhook_url="https://hooks.example/y",
        )
        for s in scheduler.schedules:
            s.next_run = datetime.now(UTC) - timedelta(seconds=1)

        fired = await scheduler.run_due(now=datetime.now(UTC))
        # One success, one error caught — overall keeps going.
        assert fired == 1
        assert any(url.endswith("/y") for url, _ in webhook.posts)

    def test_register_rejects_non_positive_interval(self, scheduler: TemplateScheduler) -> None:
        with pytest.raises(ValueError, match="interval"):
            scheduler.register(
                template_id="t1",
                org_id="org-a",
                interval_seconds=0,
                webhook_url="https://hooks.example/x",
            )
