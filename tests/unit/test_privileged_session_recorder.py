"""Tests for privileged_session_recorder."""

from __future__ import annotations

from shieldops.agents.privileged_session_recorder.models import (
    AnomalyType,
    PrivilegedSessionRecorderState,
    RecordingStage,
    SessionType,
)


class TestEnums:
    def test_anomalytype(self) -> None:
        assert AnomalyType.UNUSUAL_COMMAND == "unusual_command"
        assert len(AnomalyType) >= 3

    def test_recordingstage(self) -> None:
        assert RecordingStage.DETECT_SESSION == "detect_session"
        assert len(RecordingStage) >= 3

    def test_sessiontype(self) -> None:
        assert SessionType.SSH == "ssh"
        assert len(SessionType) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = PrivilegedSessionRecorderState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = PrivilegedSessionRecorderState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
