"""Tests for federated_learning_security."""

from __future__ import annotations

from shieldops.agents.federated_learning_security.models import (
    FederatedLearningSecurityState,
    FLStage,
    ParticipantStatus,
)


class TestEnums:
    def test_flstage(self) -> None:
        assert FLStage.INSPECT_GRADIENTS == "inspect_gradients"
        assert len(FLStage) >= 3

    def test_participantstatus(self) -> None:
        assert ParticipantStatus.TRUSTED == "trusted"
        assert len(ParticipantStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = FederatedLearningSecurityState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = FederatedLearningSecurityState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
