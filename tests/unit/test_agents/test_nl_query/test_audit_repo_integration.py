"""NL query audit module wired to repository — TDD tests (#1b)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from shieldops.agents.nl_query import audit


class _FakeAuditRepo:
    def __init__(self) -> None:
        self.logged: list[dict[str, Any]] = []

    async def log_query(
        self,
        *,
        org_id: str,
        user_id: str,
        question: str,
        generated_sql: str,
        result_count: int,
        latency_ms: float,
        cache_hit: bool = False,
        source: str = "llm",
    ) -> Any:
        entry = {
            "org_id": org_id,
            "user_id": user_id,
            "question": question,
            "generated_sql": generated_sql,
            "result_count": result_count,
            "latency_ms": latency_ms,
            "cache_hit": cache_hit,
            "source": source,
            "created_at": datetime.now(UTC),
        }
        self.logged.append(entry)
        return entry

    async def list_queries(
        self, org_id: str, *, limit: int = 50, offset: int = 0
    ) -> tuple[list[Any], int]:
        scoped = [e for e in self.logged if e["org_id"] == org_id]
        total = len(scoped)
        return scoped[offset : offset + limit], total


@pytest.fixture(autouse=True)
def reset_module() -> None:
    audit.set_repository(None)
    audit.clear_audit_log()
    yield
    audit.set_repository(None)
    audit.clear_audit_log()


class TestAuditRepoInjection:
    @pytest.mark.asyncio
    async def test_log_query_uses_repo_when_injected(self) -> None:
        repo = _FakeAuditRepo()
        audit.set_repository(repo)

        await audit.log_query(
            org_id="org-a",
            user_id="u1",
            question="show alerts",
            generated_sql="SELECT 1",
            result_count=3,
            latency_ms=12.5,
        )

        assert len(repo.logged) == 1
        assert repo.logged[0]["question"] == "show alerts"
        assert repo.logged[0]["org_id"] == "org-a"

    @pytest.mark.asyncio
    async def test_log_query_falls_back_to_in_memory_when_no_repo(self) -> None:
        # No set_repository call — should use in-memory ring buffer
        entry = await audit.log_query(
            org_id="org-b",
            user_id="u2",
            question="fallback query",
            generated_sql="SELECT 2",
            result_count=0,
            latency_ms=1.0,
        )
        assert entry.question == "fallback query"
        # list_queries returns the in-memory buffer
        rows, total = await audit.list_queries(org_id="org-b")
        assert total == 1
        assert rows[0]["question"] == "fallback query"

    @pytest.mark.asyncio
    async def test_list_queries_reads_from_repo_when_injected(self) -> None:
        repo = _FakeAuditRepo()
        audit.set_repository(repo)

        await audit.log_query(
            org_id="org-a",
            user_id="u",
            question="q1",
            generated_sql="SELECT 1",
            result_count=1,
            latency_ms=1.0,
        )
        await audit.log_query(
            org_id="org-b",
            user_id="u",
            question="q2",
            generated_sql="SELECT 2",
            result_count=1,
            latency_ms=1.0,
        )

        rows_a, total_a = await audit.list_queries(org_id="org-a")
        rows_b, total_b = await audit.list_queries(org_id="org-b")
        assert total_a == 1
        assert total_b == 1
        assert rows_a[0]["question"] == "q1"
        assert rows_b[0]["question"] == "q2"
