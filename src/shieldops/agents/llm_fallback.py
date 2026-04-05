"""Shared LLM fallback utilities for agent nodes.

Provides a standardized pattern for LLM calls with heuristic fallback,
eliminating inconsistent try/except blocks across 499 agents.
"""

from __future__ import annotations

from typing import Any, TypeVar

import structlog
from pydantic import BaseModel

logger = structlog.get_logger()

T = TypeVar("T", bound=BaseModel)


async def llm_with_fallback[T: BaseModel](
    system_prompt: str,
    user_prompt: str,
    schema: type[T],
    *,
    agent_name: str = "",
    node_name: str = "",
    fallback_fn: Any | None = None,
    fallback_value: dict[str, Any] | None = None,
) -> T | dict[str, Any]:
    """Call llm_structured with standardized fallback.

    Args:
        system_prompt: System instructions for the LLM.
        user_prompt: The data/context to analyze.
        schema: Pydantic model for structured output.
        agent_name: Agent identifier for logging.
        node_name: Node identifier for logging.
        fallback_fn: Callable that returns a fallback dict. Called on LLM failure.
        fallback_value: Static fallback dict. Used if fallback_fn is None.

    Returns:
        LLM result (Pydantic model or dict) on success, fallback on failure.
    """
    try:
        from shieldops.utils.llm import llm_structured

        result = await llm_structured(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            schema=schema,
        )
        logger.debug(
            "llm_fallback.success",
            agent=agent_name,
            node=node_name,
            schema=schema.__name__,
        )
        return result  # type: ignore[return-value]
    except Exception as e:
        logger.debug(
            "llm_fallback.using_heuristic",
            agent=agent_name,
            node=node_name,
            error=str(e)[:200],
        )
        if fallback_fn is not None:
            try:
                return fallback_fn()
            except Exception as fb_err:
                logger.warning(
                    "llm_fallback.fallback_fn_failed",
                    agent=agent_name,
                    error=str(fb_err),
                )

        if fallback_value is not None:
            return fallback_value

        # Last resort: return empty schema defaults
        try:
            return schema()
        except Exception:
            return {}


async def llm_classify(
    text: str,
    categories: list[str],
    *,
    agent_name: str = "",
    default_category: str = "",
) -> str:
    """Quick LLM classification with keyword-based fallback.

    Args:
        text: Text to classify.
        categories: Valid category names.
        agent_name: For logging.
        default_category: Returned on failure. Defaults to first category.

    Returns:
        The selected category string.
    """
    if not categories:
        return default_category

    fallback = default_category or categories[0]

    try:
        from shieldops.utils.llm import llm_analyze

        result = await llm_analyze(
            system_prompt=(
                f"Classify the following text into exactly one of these categories: "
                f"{', '.join(categories)}. Respond with only the category name."
            ),
            user_prompt=text[:2000],
        )
        content = result.get("content", "").strip().lower()
        for cat in categories:
            if cat.lower() in content:
                return cat
        return fallback
    except Exception:
        logger.debug("llm_classify.fallback", agent=agent_name)
        # Keyword-based fallback
        text_lower = text.lower()
        for cat in categories:
            if cat.lower() in text_lower:
                return cat
        return fallback
