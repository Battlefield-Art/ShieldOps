"""Tests for tokenization_manager."""

from __future__ import annotations

from shieldops.agents.tokenization_manager.models import (
    TokenizationManagerState,
    TokenStage,
    TokenType,
)


class TestEnums:
    def test_tokenstage(self) -> None:
        assert TokenStage.DISCOVER_FIELDS == "discover_fields"
        assert len(TokenStage) >= 3

    def test_tokentype(self) -> None:
        assert TokenType.FORMAT_PRESERVING == "format_preserving"
        assert len(TokenType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = TokenizationManagerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = TokenizationManagerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
