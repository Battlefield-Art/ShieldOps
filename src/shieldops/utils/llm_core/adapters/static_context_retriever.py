"""Static + null context retrievers for contract tests."""

from __future__ import annotations

from shieldops.utils.llm_core.types import ContextChunk


class NullContextRetriever:
    """Returns an empty list for every query. Default for tests that
    don't exercise the context-hub path."""

    async def retrieve(
        self,
        query: str,  # noqa: ARG002
        *,
        tenant_id: str | None = None,  # noqa: ARG002
        k: int = 5,  # noqa: ARG002
    ) -> list[ContextChunk]:
        return []


class StaticContextRetriever:
    """Returns a pre-seeded list regardless of the query.

    Tests use this to prove the orchestrator prepends context chunks
    to the prompt before calling the provider.
    """

    def __init__(self, chunks: list[ContextChunk]) -> None:
        self._chunks = list(chunks)

    async def retrieve(
        self,
        query: str,  # noqa: ARG002
        *,
        tenant_id: str | None = None,  # noqa: ARG002
        k: int = 5,
    ) -> list[ContextChunk]:
        return self._chunks[:k]
