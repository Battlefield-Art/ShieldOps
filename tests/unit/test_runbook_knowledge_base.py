"""Tests for runbook_knowledge_base."""

from __future__ import annotations

from shieldops.agents.runbook_knowledge_base.models import (
    KBStage,
    RecommendationQuality,
    RunbookCategory,
    RunbookKnowledgeBaseState,
)


class TestEnums:
    def test_kbstage(self) -> None:
        assert KBStage.INDEX_RUNBOOKS == "index_runbooks"
        assert len(KBStage) >= 3

    def test_recommendationquality(self) -> None:
        assert RecommendationQuality.EXACT_MATCH == "exact_match"
        assert len(RecommendationQuality) >= 3

    def test_runbookcategory(self) -> None:
        assert RunbookCategory.INCIDENT_RESPONSE == "incident_response"
        assert len(RunbookCategory) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = RunbookKnowledgeBaseState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = RunbookKnowledgeBaseState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
