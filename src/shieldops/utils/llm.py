"""Shared LLM client for ShieldOps agents.

RFC #248 PR-4 — ``llm_structured`` is now a thin shim that delegates
into :class:`shieldops.utils.llm_core.orchestrator.LLMOrchestrator`
when one is installed (via ``set_llm_orchestrator`` during FastAPI
lifespan). If no orchestrator is installed — e.g., during script
imports outside the app, during tests that predate PR-4, or on the
exception path — the shim falls back to the legacy direct
``ChatAnthropic`` call so 1,851 callers keep working unchanged.

The positional signature ``(system_prompt, user_prompt, schema)``
is preserved bit-for-bit. PR-5 will delete ``llm_router.py`` and
``context_hub.py``; PR-6 will dedupe the metrics helpers.
"""

from __future__ import annotations

from typing import Any

import structlog
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel

from shieldops.config import settings
from shieldops.utils.llm_core.composition import get_llm_orchestrator
from shieldops.utils.llm_core.types import LLMRequest

logger = structlog.get_logger()

# Module-level singleton (lazy-initialized) — used by the legacy
# fallback path when no LLMOrchestrator is installed.
_llm_instance: ChatAnthropic | None = None

# Legacy shim identifier used as the agent_id on synthesized
# :class:`LLMRequest` instances so the FitnessRecorder can bucket
# shim-originated calls separately from migrated call sites.
_LEGACY_SHIM_AGENT_ID = "legacy-shim"


def get_llm() -> ChatAnthropic:
    """Get or create the shared LLM client (legacy fallback path)."""
    global _llm_instance
    if _llm_instance is None:
        _llm_instance = ChatAnthropic(  # type: ignore[call-arg]
            model=settings.anthropic_model,
            api_key=settings.anthropic_api_key,  # type: ignore[arg-type]
            max_tokens=4096,
            temperature=0.1,  # Low temp for deterministic infrastructure reasoning
        )
    return _llm_instance


async def llm_analyze(
    system_prompt: str,
    user_prompt: str,
    response_schema: type[BaseModel] | None = None,
) -> dict[str, Any]:
    """Run an LLM analysis with optional structured output.

    Args:
        system_prompt: System instructions for the analysis task.
        user_prompt: The data/context to analyze.
        response_schema: If provided, parse response as this Pydantic model.

    Returns:
        Parsed dict from LLM response.
    """
    llm = get_llm()
    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt),
    ]

    if response_schema is not None:
        parser = JsonOutputParser(pydantic_object=response_schema)
        format_instructions = parser.get_format_instructions()
        messages[0] = SystemMessage(content=f"{system_prompt}\n\n{format_instructions}")
        response = await llm.ainvoke(messages)
        content_str = (
            str(response.content) if not isinstance(response.content, str) else response.content
        )
        parsed: dict[str, Any] = await parser.aparse(content_str)
        return parsed

    response = await llm.ainvoke(messages)
    return {"content": response.content}


async def _llm_structured_legacy(
    system_prompt: str,
    user_prompt: str,
    schema: type[BaseModel],
) -> dict[str, Any] | BaseModel:
    """The legacy direct-``ChatAnthropic`` path preserved as a fallback.

    This is the exact body ``llm_structured`` had before RFC #248 PR-4.
    Agents running outside the FastAPI lifespan (scripts, tests that
    predate PR-4, one-off imports) keep hitting this path so behavior
    is bit-for-bit unchanged.
    """
    llm = get_llm()
    structured_llm = llm.with_structured_output(schema)
    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_prompt),
    ]
    return await structured_llm.ainvoke(messages)


async def llm_structured(
    system_prompt: str,
    user_prompt: str,
    schema: type[BaseModel],
) -> dict[str, Any] | BaseModel:
    """Run LLM analysis and return a validated Pydantic model.

    Delegates to the installed
    :class:`shieldops.utils.llm_core.orchestrator.LLMOrchestrator`
    when one is registered (via ``set_llm_orchestrator`` in
    ``api/app.py`` lifespan). Falls back to the direct
    ``ChatAnthropic`` path when no orchestrator is installed or when
    delegation raises — this preserves bit-for-bit behavior for the
    1,851 existing call sites.

    The positional signature ``(system_prompt, user_prompt, schema)``
    is frozen — do not add positional parameters or change the order.
    """
    try:
        orch = get_llm_orchestrator()
    except RuntimeError:
        # No orchestrator installed — use the legacy path.
        return await _llm_structured_legacy(system_prompt, user_prompt, schema)

    # Register the schema on the provider if it supports ad-hoc
    # registration (Anthropic adapter does; fake providers ignore
    # response_model_name entirely and don't need a registry).
    provider = orch._deps.provider  # noqa: SLF001 — intentional shim reach-in
    register = getattr(provider, "register_schema", None)
    if register is not None:
        try:
            register(schema.__name__, schema)
        except ValueError as exc:
            # Name collision on a *different* class — the caller
            # shadowed an existing registered model. Fall back to
            # legacy so we don't mis-parse.
            logger.warning(
                "llm_structured.schema_collision",
                schema=schema.__name__,
                error=str(exc),
            )
            return await _llm_structured_legacy(system_prompt, user_prompt, schema)

    req = LLMRequest(
        prompt=user_prompt,
        response_model_name=schema.__name__,
        agent_id=_LEGACY_SHIM_AGENT_ID,
        system_prompt=system_prompt,
    )

    try:
        response = await orch.call(req)
    except Exception as exc:  # noqa: BLE001 — shim must never crash callers
        logger.warning(
            "llm_structured.orchestrator_failed_fallback_to_legacy",
            schema=schema.__name__,
            error=str(exc),
        )
        return await _llm_structured_legacy(system_prompt, user_prompt, schema)

    return response.parsed  # type: ignore[no-any-return]
