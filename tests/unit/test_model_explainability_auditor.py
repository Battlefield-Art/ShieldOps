"""Tests for model_explainability_auditor."""

from __future__ import annotations

from shieldops.agents.model_explainability_auditor.models import (
    AuditStage,
    ComplianceLevel,
    ExplainMethod,
    ModelExplainabilityAuditorState,
)


class TestEnums:
    def test_auditstage(self) -> None:
        assert AuditStage.COLLECT_PREDICTIONS == "collect_predictions"
        assert len(AuditStage) >= 3

    def test_compliancelevel(self) -> None:
        assert ComplianceLevel.FULLY_EXPLAINABLE == "fully_explainable"
        assert len(ComplianceLevel) >= 3

    def test_explainmethod(self) -> None:
        assert ExplainMethod.SHAP == "shap"
        assert len(ExplainMethod) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = ModelExplainabilityAuditorState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = ModelExplainabilityAuditorState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
