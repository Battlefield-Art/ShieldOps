"""Tests for security_copilot."""

from __future__ import annotations

from shieldops.agents.security_copilot.models import (
    CopilotStage,
    QueryType,
    ResponseConfidence,
    SecurityCopilotState,
)


class TestEnums:
    def test_copilot_stage(self) -> None:
        assert CopilotStage.PARSE_QUERY == "parse_query"
        assert len(CopilotStage) >= 3

    def test_query_type(self) -> None:
        assert QueryType.THREAT_HUNT == "threat_hunt"
        assert len(QueryType) >= 3

    def test_response_confidence(self) -> None:
        assert ResponseConfidence.DEFINITIVE == "definitive"
        assert len(ResponseConfidence) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SecurityCopilotState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SecurityCopilotState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
