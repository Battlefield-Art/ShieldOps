"""Unit tests for iac_security_scanner."""

from __future__ import annotations

from shieldops.agents.iac_security_scanner.models import (
    IACProvider,
    IACScannerState,
    IACScanStage,
    MisconfigSeverity,
)


class TestEnums:
    def test_iacprovider(self) -> None:
        assert IACProvider.TERRAFORM == "terraform"
        assert len(IACProvider) >= 3

    def test_iacscanstage(self) -> None:
        assert IACScanStage.DISCOVER_TEMPLATES == "discover_templates"
        assert len(IACScanStage) >= 3

    def test_misconfigseverity(self) -> None:
        assert MisconfigSeverity.CRITICAL == "critical"
        assert len(MisconfigSeverity) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = IACScannerState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = IACScannerState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
