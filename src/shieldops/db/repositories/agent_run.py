"""Repository for agent execution run persistence."""

from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shieldops.db.models_agent_run import AgentRun, AgentRunStatus

logger = structlog.get_logger()


class AgentRunRepository:
    """Async CRUD repository for AgentRun records."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    async def create_run(
        self,
        agent_name: str,
        org_id: str,
        input_data: dict[str, Any] | None = None,
        status: str = AgentRunStatus.PENDING,
    ) -> AgentRun:
        """Create a new agent run record."""
        async with self._sf() as session:
            record = AgentRun(
                agent_name=agent_name,
                org_id=org_id,
                status=status,
                input_data=input_data or {},
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)
            logger.info(
                "agent_run_created",
                run_id=record.id,
                agent_name=agent_name,
                org_id=org_id,
            )
            return record

    async def get_run(self, run_id: str) -> AgentRun | None:
        """Fetch a single run by ID."""
        async with self._sf() as session:
            return await session.get(AgentRun, run_id)

    async def list_runs(
        self,
        agent_name: str | None = None,
        org_id: str | None = None,
        status: str | None = None,
        page: int = 1,
        limit: int = 50,
    ) -> tuple[list[AgentRun], int]:
        """List runs with optional filters.

        Returns a tuple of (runs, total_count) for pagination.
        """
        async with self._sf() as session:
            stmt = select(AgentRun).order_by(AgentRun.created_at.desc())
            count_stmt = select(func.count()).select_from(AgentRun)

            if agent_name:
                stmt = stmt.where(AgentRun.agent_name == agent_name)
                count_stmt = count_stmt.where(AgentRun.agent_name == agent_name)
            if org_id:
                stmt = stmt.where(AgentRun.org_id == org_id)
                count_stmt = count_stmt.where(AgentRun.org_id == org_id)
            if status:
                stmt = stmt.where(AgentRun.status == status)
                count_stmt = count_stmt.where(AgentRun.status == status)

            offset = (page - 1) * limit
            stmt = stmt.offset(offset).limit(limit)

            result = await session.execute(stmt)
            runs = list(result.scalars().all())

            count_result = await session.execute(count_stmt)
            total = count_result.scalar_one()

            return runs, total

    async def update_run_status(self, run_id: str, status: str) -> AgentRun | None:
        """Update the status of an existing run."""
        async with self._sf() as session:
            record = await session.get(AgentRun, run_id)
            if record is None:
                return None
            record.status = status
            await session.commit()
            await session.refresh(record)
            logger.info(
                "agent_run_status_updated",
                run_id=run_id,
                status=status,
            )
            return record

    async def update_run_result(
        self,
        run_id: str,
        status: str,
        output_data: dict[str, Any] | None = None,
        error_message: str | None = None,
        duration_ms: int = 0,
        token_usage: dict[str, Any] | None = None,
    ) -> AgentRun | None:
        """Update a run with its final result (output, error, duration, tokens)."""
        async with self._sf() as session:
            record = await session.get(AgentRun, run_id)
            if record is None:
                return None
            record.status = status
            if output_data is not None:
                record.output_data = output_data
            if error_message is not None:
                record.error_message = error_message
            record.duration_ms = duration_ms
            if token_usage is not None:
                record.token_usage = token_usage
            await session.commit()
            await session.refresh(record)
            logger.info(
                "agent_run_result_updated",
                run_id=run_id,
                status=status,
                duration_ms=duration_ms,
            )
            return record
