"""NL Query SOC template end-to-end — TDD tests (#3)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from shieldops.agents.nl_query.models import NLQueryResponse, OutputFormat


class _FakeRunner:
    """A minimal stub that records the last request it ran."""

    def __init__(self) -> None:
        self.last_request: Any = None
        self.last_org_id: str = ""

    async def run(self, request: Any, *, org_id: str) -> NLQueryResponse:
        self.last_request = request
        self.last_org_id = org_id
        return NLQueryResponse(
            question=request.question,
            sql="SELECT 1",
            format=OutputFormat.MARKDOWN_TABLE,
            results=[{"ok": 1}],
            row_count=1,
            summary="",
            markdown="| ok |\n| --- |\n| 1 |",
            source="heuristic",
            error="",
            duration_ms=5,
        )


class TestRunTemplate:
    @pytest.mark.asyncio
    async def test_run_known_template_executes_its_question(self) -> None:
        from shieldops.agents.nl_query.template_runner import run_template

        runner = _FakeRunner()
        result = await run_template(
            template_id="daily_threat_briefing",
            org_id="org-a",
            runner=runner,
        )
        assert result is not None
        assert runner.last_org_id == "org-a"
        assert runner.last_request is not None
        assert "critical and high severity" in runner.last_request.question

    @pytest.mark.asyncio
    async def test_run_unknown_template_raises(self) -> None:
        from shieldops.agents.nl_query.template_runner import (
            TemplateNotFoundError,
            run_template,
        )

        runner = _FakeRunner()
        with pytest.raises(TemplateNotFoundError):
            await run_template(
                template_id="nonexistent",
                org_id="org-a",
                runner=runner,
            )

    @pytest.mark.asyncio
    async def test_run_template_passes_response_through(self) -> None:
        from shieldops.agents.nl_query.template_runner import run_template

        runner = _FakeRunner()
        result = await run_template(
            template_id="daily_threat_briefing",
            org_id="org-b",
            runner=runner,
        )
        assert result.row_count == 1
        assert result.markdown.startswith("| ok |")
        assert result.source == "heuristic"


class TestTemplateRunnerAPI:
    def test_list_templates_endpoint(self) -> None:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from shieldops.api.auth.dependencies import get_current_user
        from shieldops.api.routes import nl_query_templates

        app = FastAPI()
        app.include_router(nl_query_templates.router)

        async def _user() -> MagicMock:
            u = MagicMock()
            u.org_id = "test-org"
            u.id = "test-user"
            return u

        app.dependency_overrides[get_current_user] = _user

        client = TestClient(app)
        r = client.get("/query/nl/templates")
        assert r.status_code == 200
        data = r.json()
        assert "templates" in data
        assert len(data["templates"]) >= 5
        assert all("id" in t and "question" in t for t in data["templates"])

    def test_run_template_endpoint(self) -> None:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from shieldops.api.auth.dependencies import get_current_user
        from shieldops.api.routes import nl_query_templates

        app = FastAPI()
        app.include_router(nl_query_templates.router)

        # Inject a fake runner
        fake = _FakeRunner()
        nl_query_templates.set_runner(fake)

        async def _user() -> MagicMock:
            u = MagicMock()
            u.org_id = "test-org"
            u.id = "test-user"
            return u

        app.dependency_overrides[get_current_user] = _user

        client = TestClient(app)
        r = client.post("/query/nl/templates/daily_threat_briefing/run")
        assert r.status_code == 200
        data = r.json()
        assert data["row_count"] == 1
        assert fake.last_org_id == "test-org"

    def test_run_unknown_template_returns_404(self) -> None:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from shieldops.api.auth.dependencies import get_current_user
        from shieldops.api.routes import nl_query_templates

        app = FastAPI()
        app.include_router(nl_query_templates.router)
        nl_query_templates.set_runner(_FakeRunner())

        async def _user() -> AsyncMock:
            u = MagicMock()
            u.org_id = "test-org"
            u.id = "test-user"
            return u

        app.dependency_overrides[get_current_user] = _user

        client = TestClient(app)
        r = client.post("/query/nl/templates/nonexistent/run")
        assert r.status_code == 404
