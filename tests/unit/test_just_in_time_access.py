"""Tests for just_in_time_access."""

from __future__ import annotations

from shieldops.agents.just_in_time_access.models import (
    AccessType,
    JITStage,
    JustInTimeAccessState,
    RequestStatus,
)


class TestEnums:
    def test_accesstype(self) -> None:
        assert AccessType.ADMIN == "admin"
        assert len(AccessType) >= 3

    def test_jitstage(self) -> None:
        assert JITStage.RECEIVE_REQUEST == "receive_request"
        assert len(JITStage) >= 3

    def test_requeststatus(self) -> None:
        assert RequestStatus.PENDING == "pending"
        assert len(RequestStatus) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = JustInTimeAccessState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = JustInTimeAccessState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
