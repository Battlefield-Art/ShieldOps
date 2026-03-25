"""Repository layer for AI Security Control Plane models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shieldops.db.models_ai_security import (
    FirewallEvent,
    MCPServer,
    NHIdentity,
    ShadowAIDetection,
    Situation,
    SituationAction,
    SituationFinding,
)

logger = structlog.get_logger()


class AISecurityRepository:
    """Persistence repository for AI Security Control Plane domain objects."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    # ── Situations ─────────────────────────────────────────────────────

    async def create_situation(self, **kwargs: Any) -> Situation:
        """Create a new security situation."""
        async with self._sf() as session:
            record = Situation(**kwargs)
            session.add(record)
            await session.commit()
            await session.refresh(record)
            logger.info("situation_created", situation_id=record.id, severity=record.severity)
            return record

    async def get_situation(self, situation_id: str) -> Situation | None:
        """Fetch a situation by ID."""
        async with self._sf() as session:
            return await session.get(Situation, situation_id)

    async def list_situations(
        self,
        status: str | None = None,
        severity: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Situation]:
        """List situations with optional filters."""
        async with self._sf() as session:
            stmt = select(Situation).order_by(Situation.created_at.desc())
            if status:
                stmt = stmt.where(Situation.status == status)
            if severity:
                stmt = stmt.where(Situation.severity == severity)
            stmt = stmt.offset(offset).limit(limit)
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def update_situation_status(self, situation_id: str, new_status: str) -> Situation | None:
        """Transition a situation to a new status, setting timestamps as needed."""
        async with self._sf() as session:
            record = await session.get(Situation, situation_id)
            if record is None:
                return None
            record.status = new_status
            now = datetime.now(UTC)
            if new_status == "acknowledged" and record.acknowledged_at is None:
                record.acknowledged_at = now
                if record.created_at:
                    record.mtta_seconds = int((now - record.created_at).total_seconds())
            elif new_status in ("resolved", "closed") and record.resolved_at is None:
                record.resolved_at = now
                if record.created_at:
                    record.mttr_seconds = int((now - record.created_at).total_seconds())
            await session.commit()
            await session.refresh(record)
            logger.info(
                "situation_status_updated",
                situation_id=situation_id,
                new_status=new_status,
            )
            return record

    # ── Situation Findings ─────────────────────────────────────────────

    async def add_finding(self, **kwargs: Any) -> SituationFinding:
        """Add a finding to a situation."""
        async with self._sf() as session:
            record = SituationFinding(**kwargs)
            session.add(record)
            await session.commit()
            await session.refresh(record)
            return record

    # ── Situation Actions ──────────────────────────────────────────────

    async def add_action(self, **kwargs: Any) -> SituationAction:
        """Record an action taken on a situation."""
        async with self._sf() as session:
            record = SituationAction(**kwargs)
            session.add(record)
            await session.commit()
            await session.refresh(record)
            return record

    # ── NHI Management ─────────────────────────────────────────────────

    async def create_nhi(self, **kwargs: Any) -> NHIdentity:
        """Register a non-human identity."""
        async with self._sf() as session:
            record = NHIdentity(**kwargs)
            session.add(record)
            await session.commit()
            await session.refresh(record)
            logger.info("nhi_created", nhi_id=record.id, nhi_type=record.nhi_type)
            return record

    async def get_nhi(self, nhi_id: str) -> NHIdentity | None:
        """Fetch a non-human identity by ID."""
        async with self._sf() as session:
            return await session.get(NHIdentity, nhi_id)

    async def list_nhis(
        self,
        nhi_type: str | None = None,
        provider: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[NHIdentity]:
        """List NHIs with optional filters."""
        async with self._sf() as session:
            stmt = select(NHIdentity).order_by(NHIdentity.created_at.desc())
            if nhi_type:
                stmt = stmt.where(NHIdentity.nhi_type == nhi_type)
            if provider:
                stmt = stmt.where(NHIdentity.provider == provider)
            if status:
                stmt = stmt.where(NHIdentity.status == status)
            stmt = stmt.limit(limit)
            result = await session.execute(stmt)
            return list(result.scalars().all())

    # ── Shadow AI ──────────────────────────────────────────────────────

    async def record_shadow_ai(self, **kwargs: Any) -> ShadowAIDetection:
        """Record a shadow AI detection."""
        async with self._sf() as session:
            record = ShadowAIDetection(**kwargs)
            session.add(record)
            await session.commit()
            await session.refresh(record)
            logger.info("shadow_ai_detected", detection_id=record.id, provider=record.provider)
            return record

    async def list_shadow_ai(
        self,
        status: str | None = None,
        limit: int = 50,
    ) -> list[ShadowAIDetection]:
        """List shadow AI detections."""
        async with self._sf() as session:
            stmt = select(ShadowAIDetection).order_by(ShadowAIDetection.last_seen_at.desc())
            if status:
                stmt = stmt.where(ShadowAIDetection.status == status)
            stmt = stmt.limit(limit)
            result = await session.execute(stmt)
            return list(result.scalars().all())

    # ── Firewall Events ────────────────────────────────────────────────

    async def record_firewall_event(self, **kwargs: Any) -> FirewallEvent:
        """Record an AI firewall event."""
        async with self._sf() as session:
            record = FirewallEvent(**kwargs)
            session.add(record)
            await session.commit()
            await session.refresh(record)
            return record

    async def list_firewall_events(
        self,
        agent_id: str | None = None,
        action_taken: str | None = None,
        limit: int = 100,
    ) -> list[FirewallEvent]:
        """List firewall events with optional filters."""
        async with self._sf() as session:
            stmt = select(FirewallEvent).order_by(FirewallEvent.timestamp.desc())
            if agent_id:
                stmt = stmt.where(FirewallEvent.agent_id == agent_id)
            if action_taken:
                stmt = stmt.where(FirewallEvent.action_taken == action_taken)
            stmt = stmt.limit(limit)
            result = await session.execute(stmt)
            return list(result.scalars().all())

    # ── MCP Servers ────────────────────────────────────────────────────

    async def register_mcp_server(self, **kwargs: Any) -> MCPServer:
        """Register an MCP server."""
        async with self._sf() as session:
            record = MCPServer(**kwargs)
            session.add(record)
            await session.commit()
            await session.refresh(record)
            logger.info("mcp_server_registered", server_id=record.id, name=record.name)
            return record

    async def get_mcp_server(self, server_id: str) -> MCPServer | None:
        """Fetch an MCP server by ID."""
        async with self._sf() as session:
            return await session.get(MCPServer, server_id)

    async def list_mcp_servers(
        self,
        trust_level: str | None = None,
        limit: int = 50,
    ) -> list[MCPServer]:
        """List registered MCP servers."""
        async with self._sf() as session:
            stmt = select(MCPServer).order_by(MCPServer.created_at.desc())
            if trust_level:
                stmt = stmt.where(MCPServer.trust_level == trust_level)
            stmt = stmt.limit(limit)
            result = await session.execute(stmt)
            return list(result.scalars().all())
