"""Tests for agent execution persistence — repositories, API endpoints, and helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Lightweight fakes for SQLAlchemy async session to avoid a real database.
# ---------------------------------------------------------------------------


class FakeAgentRun:
    """In-memory fake of the AgentRun ORM model."""

    def __init__(self, **kwargs: Any) -> None:
        from uuid import uuid4

        self.id = kwargs.get("id", f"run-{uuid4().hex[:16]}")
        self.agent_name = kwargs.get("agent_name", "investigation")
        self.status = kwargs.get("status", "pending")
        self.input_data = kwargs.get("input_data", {})
        self.output_data = kwargs.get("output_data", {})
        self.error_message = kwargs.get("error_message")
        self.duration_ms = kwargs.get("duration_ms", 0)
        self.token_usage = kwargs.get(
            "token_usage",
            {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )
        self.org_id = kwargs.get("org_id", "org-test")
        self.created_at = kwargs.get("created_at", datetime.now(UTC))
        self.updated_at = kwargs.get("updated_at", datetime.now(UTC))


class FakeAuditEntry:
    """In-memory fake of the AuditEntry ORM model."""

    def __init__(self, **kwargs: Any) -> None:
        from uuid import uuid4

        self.id = kwargs.get("id", f"ae-{uuid4().hex[:16]}")
        self.action = kwargs.get("action", "agent.execute")
        self.actor = kwargs.get("actor", "investigation")
        self.target = kwargs.get("target", "alert-123")
        self.result = kwargs.get("result", "success")
        self.metadata_ = kwargs.get("metadata_", {})
        self.org_id = kwargs.get("org_id", "org-test")
        self.created_at = kwargs.get("created_at", datetime.now(UTC))


# ── Repository Unit Tests ─────────────────────────────────────────────


class TestAgentRunRepository:
    """Test AgentRunRepository CRUD operations using mocked sessions."""

    @pytest.fixture()
    def mock_session_factory(self) -> MagicMock:
        session = AsyncMock()
        session.add = MagicMock()
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=session)
        ctx.__aexit__ = AsyncMock(return_value=False)
        factory = MagicMock(return_value=ctx)
        factory._session = session  # stash for test access
        return factory

    @pytest.mark.asyncio()
    async def test_create_run(self, mock_session_factory: MagicMock) -> None:
        from shieldops.db.repositories.agent_run import AgentRunRepository

        session = mock_session_factory._session
        fake_run = FakeAgentRun(agent_name="soc_analyst", org_id="org-abc")
        session.refresh = AsyncMock(return_value=None)
        session.commit = AsyncMock(return_value=None)

        # Patch AgentRun constructor to return our fake
        with patch(
            "shieldops.db.repositories.agent_run.AgentRun",
            return_value=fake_run,
        ):
            repo = AgentRunRepository(mock_session_factory)
            result = await repo.create_run(
                agent_name="soc_analyst",
                org_id="org-abc",
                input_data={"alert_id": "alert-1"},
            )

        assert result.agent_name == "soc_analyst"
        assert result.org_id == "org-abc"
        session.add.assert_called_once_with(fake_run)
        session.commit.assert_awaited_once()

    @pytest.mark.asyncio()
    async def test_get_run(self, mock_session_factory: MagicMock) -> None:
        from shieldops.db.repositories.agent_run import AgentRunRepository

        session = mock_session_factory._session
        fake_run = FakeAgentRun(id="run-abc123")
        session.get = AsyncMock(return_value=fake_run)

        repo = AgentRunRepository(mock_session_factory)
        result = await repo.get_run("run-abc123")

        assert result is not None
        assert result.id == "run-abc123"

    @pytest.mark.asyncio()
    async def test_get_run_not_found(self, mock_session_factory: MagicMock) -> None:
        from shieldops.db.repositories.agent_run import AgentRunRepository

        session = mock_session_factory._session
        session.get = AsyncMock(return_value=None)

        repo = AgentRunRepository(mock_session_factory)
        result = await repo.get_run("run-nonexistent")

        assert result is None

    @pytest.mark.asyncio()
    async def test_update_run_status(self, mock_session_factory: MagicMock) -> None:
        from shieldops.db.repositories.agent_run import AgentRunRepository

        session = mock_session_factory._session
        fake_run = FakeAgentRun(id="run-abc123", status="pending")
        session.get = AsyncMock(return_value=fake_run)
        session.commit = AsyncMock(return_value=None)
        session.refresh = AsyncMock(return_value=None)

        repo = AgentRunRepository(mock_session_factory)
        result = await repo.update_run_status("run-abc123", "running")

        assert result is not None
        assert result.status == "running"

    @pytest.mark.asyncio()
    async def test_update_run_result(self, mock_session_factory: MagicMock) -> None:
        from shieldops.db.repositories.agent_run import AgentRunRepository

        session = mock_session_factory._session
        fake_run = FakeAgentRun(id="run-abc123")
        session.get = AsyncMock(return_value=fake_run)
        session.commit = AsyncMock(return_value=None)
        session.refresh = AsyncMock(return_value=None)

        repo = AgentRunRepository(mock_session_factory)
        token_usage = {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
        result = await repo.update_run_result(
            run_id="run-abc123",
            status="completed",
            output_data={"verdict": "true_positive"},
            duration_ms=1500,
            token_usage=token_usage,
        )

        assert result is not None
        assert result.status == "completed"
        assert result.output_data == {"verdict": "true_positive"}
        assert result.duration_ms == 1500
        assert result.token_usage == token_usage

    @pytest.mark.asyncio()
    async def test_update_run_result_not_found(self, mock_session_factory: MagicMock) -> None:
        from shieldops.db.repositories.agent_run import AgentRunRepository

        session = mock_session_factory._session
        session.get = AsyncMock(return_value=None)

        repo = AgentRunRepository(mock_session_factory)
        result = await repo.update_run_result(run_id="run-nonexistent", status="completed")

        assert result is None


class TestAuditEntryRepository:
    """Test AuditEntryRepository — append-only semantics."""

    @pytest.fixture()
    def mock_session_factory(self) -> MagicMock:
        session = AsyncMock()
        session.add = MagicMock()
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=session)
        ctx.__aexit__ = AsyncMock(return_value=False)
        factory = MagicMock(return_value=ctx)
        factory._session = session
        return factory

    @pytest.mark.asyncio()
    async def test_create_entry(self, mock_session_factory: MagicMock) -> None:
        from shieldops.db.repositories.audit_entry import AuditEntryRepository

        session = mock_session_factory._session
        fake_entry = FakeAuditEntry(action="agent.execute", actor="soc_analyst")
        session.commit = AsyncMock(return_value=None)
        session.refresh = AsyncMock(return_value=None)

        with patch(
            "shieldops.db.repositories.audit_entry.AuditEntry",
            return_value=fake_entry,
        ):
            repo = AuditEntryRepository(mock_session_factory)
            result = await repo.create_entry(
                action="agent.execute",
                actor="soc_analyst",
                target="alert-123",
                result="success",
                org_id="org-test",
                metadata={"confidence": 0.95},
            )

        assert result.action == "agent.execute"
        assert result.actor == "soc_analyst"
        session.add.assert_called_once_with(fake_entry)
        session.commit.assert_awaited_once()

    def test_no_update_method(self) -> None:
        """AuditEntryRepository must NOT expose update methods."""
        from shieldops.db.repositories.audit_entry import AuditEntryRepository

        assert not hasattr(AuditEntryRepository, "update_entry")
        assert not hasattr(AuditEntryRepository, "update")

    def test_no_delete_method(self) -> None:
        """AuditEntryRepository must NOT expose delete methods."""
        from shieldops.db.repositories.audit_entry import AuditEntryRepository

        assert not hasattr(AuditEntryRepository, "delete_entry")
        assert not hasattr(AuditEntryRepository, "delete")


# ── API Endpoint Tests ────────────────────────────────────────────────


class TestAgentRunsAPI:
    """Test API endpoints for agent runs and audit log."""

    @pytest.fixture()
    def mock_user(self) -> MagicMock:
        user = MagicMock()
        user.id = "usr-test123"
        user.email = "test@shieldops.dev"
        user.name = "Test User"
        user.role = "admin"
        user.is_active = True
        user.org_id = "org-test"
        return user

    def test_run_response_model(self) -> None:
        """AgentRunResponse serializes correctly."""
        from shieldops.api.routes.agent_runs import AgentRunResponse

        now = datetime.now(UTC)
        resp = AgentRunResponse(
            id="run-abc",
            agent_name="investigation",
            status="completed",
            input_data={"alert_id": "a1"},
            output_data={"verdict": "tp"},
            error_message=None,
            duration_ms=2000,
            token_usage={"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
            org_id="org-test",
            created_at=now,
            updated_at=now,
        )
        assert resp.id == "run-abc"
        assert resp.status == "completed"
        assert resp.token_usage["total_tokens"] == 150

    def test_audit_entry_response_model(self) -> None:
        """AuditEntryResponse serializes correctly."""
        from shieldops.api.routes.agent_runs import AuditEntryResponse

        now = datetime.now(UTC)
        resp = AuditEntryResponse(
            id="ae-abc",
            action="agent.execute",
            actor="soc_analyst",
            target="alert-123",
            result="success",
            metadata={"confidence": 0.95},
            org_id="org-test",
            created_at=now,
        )
        assert resp.action == "agent.execute"
        assert resp.metadata["confidence"] == 0.95

    def test_paginated_runs_response(self) -> None:
        """PaginatedRunsResponse includes pagination metadata."""
        from shieldops.api.routes.agent_runs import PaginatedRunsResponse

        resp = PaginatedRunsResponse(runs=[], total=0, page=1, limit=50)
        assert resp.total == 0
        assert resp.page == 1

    def test_extract_org_id_from_user(self) -> None:
        """_extract_org_id uses org_id attribute when available."""
        from shieldops.api.routes.agent_runs import _extract_org_id

        user = MagicMock()
        user.org_id = "org-abc"
        assert _extract_org_id(user) == "org-abc"

    def test_extract_org_id_fallback(self) -> None:
        """_extract_org_id falls back to user.id when org_id is missing."""
        from shieldops.api.routes.agent_runs import _extract_org_id

        user = MagicMock(spec=["id", "email", "name", "role", "is_active"])
        user.id = "usr-fallback"
        assert _extract_org_id(user) == "usr-fallback"


# ── Persistence Helper Tests ──────────────────────────────────────────


class TestPersistenceHelpers:
    """Test persist_agent_run() and write_audit_log() graceful degradation."""

    @pytest.mark.asyncio()
    async def test_persist_agent_run_success(self) -> None:
        from shieldops.utils.persistence import persist_agent_run

        fake_run = FakeAgentRun(id="run-success")
        mock_repo = AsyncMock()
        mock_repo.create_run.return_value = fake_run
        mock_repo.update_run_result.return_value = fake_run

        with patch(
            "shieldops.utils.persistence._get_run_repo",
            return_value=mock_repo,
        ):
            run_id = await persist_agent_run(
                agent_name="investigation",
                org_id="org-test",
                input_data={"alert": "a1"},
                output_data={"verdict": "tp"},
                duration_ms=1200,
                token_usage={"prompt_tokens": 50, "completion_tokens": 30, "total_tokens": 80},
            )

        assert run_id == "run-success"
        mock_repo.create_run.assert_awaited_once()
        mock_repo.update_run_result.assert_awaited_once()

    @pytest.mark.asyncio()
    async def test_persist_agent_run_auto_status_completed(self) -> None:
        """Status defaults to COMPLETED when no error."""
        from shieldops.utils.persistence import persist_agent_run

        fake_run = FakeAgentRun(id="run-ok")
        mock_repo = AsyncMock()
        mock_repo.create_run.return_value = fake_run
        mock_repo.update_run_result.return_value = fake_run

        with patch(
            "shieldops.utils.persistence._get_run_repo",
            return_value=mock_repo,
        ):
            await persist_agent_run(
                agent_name="remediation",
                org_id="org-test",
            )

        call_kwargs = mock_repo.create_run.call_args.kwargs
        assert call_kwargs["status"] == "completed"

    @pytest.mark.asyncio()
    async def test_persist_agent_run_auto_status_failed(self) -> None:
        """Status defaults to FAILED when error_message is set."""
        from shieldops.utils.persistence import persist_agent_run

        fake_run = FakeAgentRun(id="run-fail")
        mock_repo = AsyncMock()
        mock_repo.create_run.return_value = fake_run
        mock_repo.update_run_result.return_value = fake_run

        with patch(
            "shieldops.utils.persistence._get_run_repo",
            return_value=mock_repo,
        ):
            await persist_agent_run(
                agent_name="remediation",
                org_id="org-test",
                error_message="Connection timeout",
            )

        call_kwargs = mock_repo.create_run.call_args.kwargs
        assert call_kwargs["status"] == "failed"

    @pytest.mark.asyncio()
    async def test_persist_agent_run_graceful_on_db_failure(self) -> None:
        """persist_agent_run returns None instead of crashing on DB error."""
        from shieldops.utils.persistence import persist_agent_run

        mock_repo = AsyncMock()
        mock_repo.create_run.side_effect = RuntimeError("DB connection lost")

        with patch(
            "shieldops.utils.persistence._get_run_repo",
            return_value=mock_repo,
        ):
            result = await persist_agent_run(
                agent_name="investigation",
                org_id="org-test",
            )

        assert result is None

    @pytest.mark.asyncio()
    async def test_write_audit_log_success(self) -> None:
        from shieldops.utils.persistence import write_audit_log

        fake_entry = FakeAuditEntry(id="ae-success")
        mock_repo = AsyncMock()
        mock_repo.create_entry.return_value = fake_entry

        with patch(
            "shieldops.utils.persistence._get_audit_repo",
            return_value=mock_repo,
        ):
            entry_id = await write_audit_log(
                action="agent.execute",
                actor="soc_analyst",
                target="alert-456",
                result="success",
                org_id="org-test",
                metadata={"confidence": 0.92},
            )

        assert entry_id == "ae-success"
        mock_repo.create_entry.assert_awaited_once()

    @pytest.mark.asyncio()
    async def test_write_audit_log_graceful_on_db_failure(self) -> None:
        """write_audit_log returns None instead of crashing on DB error."""
        from shieldops.utils.persistence import write_audit_log

        mock_repo = AsyncMock()
        mock_repo.create_entry.side_effect = RuntimeError("DB unavailable")

        with patch(
            "shieldops.utils.persistence._get_audit_repo",
            return_value=mock_repo,
        ):
            result = await write_audit_log(
                action="agent.execute",
                actor="soc_analyst",
                target="alert-456",
                result="failure",
                org_id="org-test",
            )

        assert result is None


# ── Model Tests ───────────────────────────────────────────────────────


class TestAgentRunStatus:
    """Test AgentRunStatus enum values."""

    def test_status_values(self) -> None:
        from shieldops.db.models_agent_run import AgentRunStatus

        assert AgentRunStatus.PENDING == "pending"
        assert AgentRunStatus.RUNNING == "running"
        assert AgentRunStatus.COMPLETED == "completed"
        assert AgentRunStatus.FAILED == "failed"

    def test_status_is_str_enum(self) -> None:
        from enum import StrEnum

        from shieldops.db.models_agent_run import AgentRunStatus

        assert issubclass(AgentRunStatus, StrEnum)
