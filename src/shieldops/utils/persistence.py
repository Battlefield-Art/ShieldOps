"""Convenience helpers for agent execution persistence and audit logging.

These functions are designed to be called from agent code. They handle
DB failures gracefully — logging a warning rather than crashing the agent.
"""

from __future__ import annotations

from typing import Any

import structlog

from shieldops.db.models_agent_run import AgentRunStatus
from shieldops.db.repositories.agent_run import AgentRunRepository
from shieldops.db.repositories.audit_entry import AuditEntryRepository
from shieldops.db.session import get_session_factory

logger = structlog.get_logger()

# Module-level singletons, lazily initialized
_run_repo: AgentRunRepository | None = None
_audit_repo: AuditEntryRepository | None = None


def _get_run_repo() -> AgentRunRepository:
    global _run_repo
    if _run_repo is None:
        _run_repo = AgentRunRepository(get_session_factory())
    return _run_repo


def _get_audit_repo() -> AuditEntryRepository:
    global _audit_repo
    if _audit_repo is None:
        _audit_repo = AuditEntryRepository(get_session_factory())
    return _audit_repo


async def persist_agent_run(
    agent_name: str,
    org_id: str,
    input_data: dict[str, Any] | None = None,
    output_data: dict[str, Any] | None = None,
    duration_ms: int = 0,
    token_usage: dict[str, Any] | None = None,
    error_message: str | None = None,
    status: str | None = None,
) -> str | None:
    """Persist an agent run result.

    Creates a run record with the given data. If *status* is not provided,
    it defaults to COMPLETED when there is no error, or FAILED when
    *error_message* is set.

    Returns the run ID on success, or None if persistence failed.
    """
    if status is None:
        status = AgentRunStatus.FAILED if error_message else AgentRunStatus.COMPLETED

    try:
        repo = _get_run_repo()
        run = await repo.create_run(
            agent_name=agent_name,
            org_id=org_id,
            input_data=input_data,
            status=status,
        )
        # Update with result data
        await repo.update_run_result(
            run_id=run.id,
            status=status,
            output_data=output_data,
            error_message=error_message,
            duration_ms=duration_ms,
            token_usage=token_usage,
        )
        logger.info(
            "agent_run_persisted",
            run_id=run.id,
            agent_name=agent_name,
            status=status,
            duration_ms=duration_ms,
        )
        return run.id
    except Exception:
        logger.warning(
            "agent_run_persist_failed",
            agent_name=agent_name,
            org_id=org_id,
            exc_info=True,
        )
        return None


async def write_audit_log(
    action: str,
    actor: str,
    target: str,
    result: str,
    org_id: str,
    metadata: dict[str, Any] | None = None,
) -> str | None:
    """Write an immutable audit log entry.

    Returns the entry ID on success, or None if persistence failed.
    """
    try:
        repo = _get_audit_repo()
        entry = await repo.create_entry(
            action=action,
            actor=actor,
            target=target,
            result=result,
            org_id=org_id,
            metadata=metadata,
        )
        logger.info(
            "audit_entry_written",
            entry_id=entry.id,
            action=action,
            actor=actor,
            result=result,
        )
        return entry.id
    except Exception:
        logger.warning(
            "audit_entry_write_failed",
            action=action,
            actor=actor,
            target=target,
            exc_info=True,
        )
        return None
