"""Fixed classifier — returns a canned complexity for every request.

Used by contract tests that need deterministic model routing.
"""

from __future__ import annotations

from shieldops.utils.llm_core.types import Complexity, LLMRequest


class FixedClassifier:
    """Returns the same :class:`Complexity` for every request."""

    def __init__(self, complexity: Complexity = Complexity.MEDIUM) -> None:
        self._complexity = complexity

    def classify(self, request: LLMRequest) -> Complexity:  # noqa: ARG002
        return self._complexity
