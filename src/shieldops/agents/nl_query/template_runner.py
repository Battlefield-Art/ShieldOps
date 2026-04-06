"""Execute SOC workflow templates end-to-end through the NL Query runner.

Public interface::

    from shieldops.agents.nl_query.template_runner import run_template, TemplateNotFoundError

    result = await run_template(
        template_id="daily_threat_briefing",
        org_id="org-a",
        runner=nl_query_runner,  # NLQueryRunner instance
    )

The template registry is :mod:`shieldops.agents.nl_query.templates`.
"""

from __future__ import annotations

from typing import Any, Protocol

import structlog

from shieldops.agents.nl_query.models import NLQueryRequest, NLQueryResponse
from shieldops.agents.nl_query.templates import get_template

logger = structlog.get_logger(__name__)


class TemplateNotFoundError(Exception):
    """Raised when a template_id doesn't match any registered template."""


class _RunnerProtocol(Protocol):
    async def run(self, request: Any, *, org_id: str) -> NLQueryResponse: ...


async def run_template(
    *,
    template_id: str,
    org_id: str,
    runner: _RunnerProtocol,
    time_range: str | None = None,
) -> NLQueryResponse:
    """Execute a named SOC template via the NL Query runner.

    The template's ``question`` field is fed through the runner; all query
    generation, validation, execution, and formatting happens in the runner
    exactly like a user-typed query.
    """
    template = get_template(template_id)
    if template is None:
        raise TemplateNotFoundError(f"unknown template: {template_id}")

    request = NLQueryRequest(
        question=template["question"],
        time_range=time_range or "",
    )
    logger.info(
        "nl_query.template.run",
        template_id=template_id,
        org_id=org_id,
        category=template.get("category", ""),
    )
    return await runner.run(request, org_id=org_id)
