"""Unit tests for sast_scanner."""

from __future__ import annotations

from shieldops.agents.sast_scanner.models import (
    CodeLanguage,
    SASTScannerState,
    SASTStage,
)


class TestEnums:
    def test_codelanguage(self) -> None:
        assert CodeLanguage.PYTHON == "python"
        assert len(CodeLanguage) >= 3

    def test_saststage(self) -> None:
        assert SASTStage.DISCOVER_FILES == "discover_files"
        assert len(SASTStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = SASTScannerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = SASTScannerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
