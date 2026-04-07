"""Monthly token-usage report aggregator (#6 Round 3).

Sums per-org agent run counts, tokens (prompt/completion/total), and breakdown
by agent for a given calendar month. Reads from :class:`AgentRun` rows so any
agent that records ``token_usage`` automatically rolls up here.

Used by:
- Billing dashboard / customer portal "this month's usage"
- End-of-month invoicing (paired with Stripe metered billing)
- Internal capacity planning
"""

from __future__ import annotations

from calendar import monthrange
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shieldops.db.models_agent_run import AgentRun

logger = structlog.get_logger(__name__)


class MonthlyUsageReport(BaseModel):
    """Aggregated usage for a single org × month."""

    org_id: str
    year: int
    month: int
    total_runs: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_tokens: int = 0
    runs_by_agent: dict[str, int] = {}


@dataclass
class _Accumulator:
    runs: int = 0
    prompt: int = 0
    completion: int = 0
    total: int = 0
    by_agent: Counter[str] = field(default_factory=Counter)


class MonthlyUsageReporter:
    """Aggregates :class:`AgentRun` rows into a monthly usage report."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def compute(self, *, org_id: str, year: int, month: int) -> MonthlyUsageReport:
        if not 1 <= month <= 12:
            raise ValueError(f"month must be 1..12, got {month}")

        start = datetime(year, month, 1, tzinfo=UTC)
        last_day = monthrange(year, month)[1]
        end = datetime(year, month, last_day, 23, 59, 59, 999_999, tzinfo=UTC)

        stmt = select(AgentRun).where(
            AgentRun.org_id == org_id,
            AgentRun.created_at >= start,
            AgentRun.created_at <= end,
        )
        rows = list((await self._session.execute(stmt)).scalars().all())

        acc = _Accumulator()
        for row in rows:
            acc.runs += 1
            tu = row.token_usage or {}
            acc.prompt += int(tu.get("prompt_tokens", 0) or 0)
            acc.completion += int(tu.get("completion_tokens", 0) or 0)
            acc.total += int(
                tu.get("total_tokens", 0)
                or (int(tu.get("prompt_tokens", 0) or 0) + int(tu.get("completion_tokens", 0) or 0))
            )
            acc.by_agent[row.agent_name] += 1

        report = MonthlyUsageReport(
            org_id=org_id,
            year=year,
            month=month,
            total_runs=acc.runs,
            total_prompt_tokens=acc.prompt,
            total_completion_tokens=acc.completion,
            total_tokens=acc.total,
            runs_by_agent=dict(acc.by_agent),
        )
        logger.info(
            "monthly_usage_report.computed",
            org_id=org_id,
            year=year,
            month=month,
            runs=report.total_runs,
            tokens=report.total_tokens,
        )
        return report
